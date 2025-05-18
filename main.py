from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory, jsonify
from flask_socketio import SocketIO, join_room, leave_room, emit
from datetime import datetime
import sqlite3
import os
from cryptography.fernet import Fernet

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'
socketio = SocketIO(app)
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# Database setup
db = sqlite3.connect('chat.db', check_same_thread=False)
db.row_factory = sqlite3.Row

# Encryption key for messages (In practice, keep this secret & secure)
encryption_key = Fernet.generate_key()
cipher = Fernet(encryption_key)

# Store online users per room and last seen
online_users = {}
last_seen = {}

def encrypt_message(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt_message(token):
    return cipher.decrypt(token.encode()).decode()

# Helper functions for DB interactions
def get_messages(room_code):
    c = db.cursor()
    c.execute('SELECT * FROM messages WHERE room_code=? AND deleted_for_both=0 ORDER BY timestamp ASC', (room_code,))
    return [dict(row) for row in c.fetchall()]

def save_message(room_code, sender, msg_type, content):
    c = db.cursor()
    timestamp = datetime.utcnow()
    c.execute('INSERT INTO messages (room_code, sender, message_type, content, timestamp) VALUES (?, ?, ?, ?, ?)',
              (room_code, sender, msg_type, content, timestamp))
    db.commit()
    return c.lastrowid, timestamp

def update_message_edit(msg_id, content):
    c = db.cursor()
    c.execute('UPDATE messages SET content=?, edited=1 WHERE id=?', (content, msg_id))
    db.commit()

def delete_message_for_both(msg_id):
    c = db.cursor()
    c.execute('UPDATE messages SET deleted_for_both=1 WHERE id=?', (msg_id,))
    db.commit()

def delete_message_for_self(msg_id, username):
    c = db.cursor()
    # Store which users deleted for self if needed, else a simpler approach here:
    # For demo: just mark as deleted_for_both if both users deleted, else skip
    pass

def get_pinned_message(room_code):
    c = db.cursor()
    c.execute('SELECT * FROM messages WHERE room_code=? AND pinned=1', (room_code,))
    row = c.fetchone()
    return dict(row) if row else None

def update_pinned_message(room_code, msg_id):
    c = db.cursor()
    # Unpin old
    c.execute('UPDATE messages SET pinned=0 WHERE room_code=?', (room_code,))
    # Pin new
    c.execute('UPDATE messages SET pinned=1 WHERE id=?', (msg_id,))
    db.commit()

def save_message_status(msg_id, username, delivered=False, read=False):
    # Save delivery/read receipts if needed
    pass

def update_read_receipt(room_code, username, last_read_id):
    # Update read receipt tracking for user in room
    pass

def get_all_media(room_code):
    c = db.cursor()
    c.execute('SELECT * FROM messages WHERE room_code=? AND message_type IN ("image", "audio", "file") AND deleted_for_both=0', (room_code,))
    return [dict(row) for row in c.fetchall()]

def set_nickname(room_code, setter, target, nickname):
    c = db.cursor()
    # Save nickname for user in room
    pass

# Routes

@app.route('/', methods=['GET', 'POST'])
def password_entry():
    if request.method == 'POST':
        password = request.form.get('password')
        if password == 'your_password':  # Replace with your actual password check
            session['password_passed'] = True
            return redirect(url_for('login'))
        else:
            return render_template('password.html', error="Incorrect password")
    else:
        if session.get('password_passed'):
            return redirect(url_for('login'))
        return render_template('password.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        if not username or len(username) < 1:
            return render_template('login.html', error="Enter a valid username")
        session['username'] = username
        return redirect(url_for('select_room'))
    else:
        if session.get('username'):
            return redirect(url_for('select_room'))
        return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('password_entry'))

@app.route('/select_room', methods=['GET', 'POST'])
def select_room():
    if not session.get('username') or not session.get('password_passed'):
        return redirect(url_for('password_entry'))
    if request.method == 'POST':
        room_code = request.form.get('room_code')
        if not room_code or len(room_code) != 4 or not room_code.isdigit():
            return render_template('select_room.html', error="Enter a valid 4-digit room code")
        session['room_code'] = room_code

        # Add room if not exist
        c = db.cursor()
        c.execute('SELECT * FROM chatrooms WHERE room_code=?', (room_code,))
        if not c.fetchone():
            c.execute('INSERT INTO chatrooms (room_code) VALUES (?)', (room_code,))
            db.commit()

        return redirect(url_for('chatroom', room_code=room_code))
    else:
        return render_template('select_room.html')

@app.route('/chat/<room_code>')
def chatroom(room_code):
    if not session.get('username') or not session.get('password_passed'):
        return redirect(url_for('password_entry'))
    if session.get('room_code') != room_code:
        return redirect(url_for('select_room'))
    return render_template('chatroom.html', room_code=room_code, username=session['username'])

@app.route('/media/<filename>')
def media(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/get_media/<room_code>')
def get_media(room_code):
    media = get_all_media(room_code)
    return jsonify(media)

# =========== SocketIO Events ===========

@socketio.on('connect')
def on_connect():
    username = session.get('username')
    room_code = session.get('room_code')
    sid = request.sid
    if not username or not room_code:
        return False  # Reject connection

    # Initialize online_users dict for room
    if room_code not in online_users:
        online_users[room_code] = {}

    # Check max 2 users
    if len(online_users[room_code]) >= 2 and username not in online_users[room_code]:
        emit('room_full')
        return False

    # Add user to online
    online_users[room_code][username] = sid
    join_room(room_code)

    # Broadcast online status
    emit('user_online', {'username': username}, room=room_code)

    # Update last seen as now (online)
    last_seen[username] = datetime.utcnow()

    # Send chat history
    msgs = get_messages(room_code)
    # Decrypt content before sending
    for m in msgs:
        try:
            m['content'] = decrypt_message(m['content'])
        except:
            pass
    emit('chat_history', msgs)

    # Send pinned message
    pinned = get_pinned_message(room_code)
    if pinned:
        try:
            pinned['content'] = decrypt_message(pinned['content'])
        except:
            pass
        emit('pinned_message', pinned)

@socketio.on('disconnect')
def on_disconnect():
    username = session.get('username')
    room_code = session.get('room_code')
    if not username or not room_code:
        return
    # Remove user from online
    if room_code in online_users and username in online_users[room_code]:
        del online_users[room_code][username]
    leave_room(room_code)
    # Update last seen time
    last_seen[username] = datetime.utcnow()
    # Broadcast offline status with last seen
    emit('user_offline', {'username': username, 'last_seen': last_seen[username].isoformat()}, room=room_code)

@socketio.on('send_message')
def on_send_message(data):
    username = session.get('username')
    room_code = session.get('room_code')
    if not username or not room_code:
        return

    msg_type = data.get('type', 'text')
    raw_content = data.get('content', '')

    # Encrypt message content
    enc_content = encrypt_message(raw_content)

    # Save message
    msg_id, timestamp = save_message(room_code, username, msg_type, enc_content)

    # Send message to room with decrypted content for sender (for latency)
    emit('new_message', {
        'id': msg_id,
        'room_code': room_code,
        'sender': username,
        'type': msg_type,
        'content': raw_content,
        'timestamp': timestamp.isoformat(),
        'edited': False,
        'pinned': False
    }, room=room_code)

@socketio.on('typing')
def on_typing(data):
    username = session.get('username')
    room_code = session.get('room_code')
    if not username or not room_code:
        return
    emit('user_typing', {'username': username}, room=room_code, include_self=False)

@socketio.on('edit_message')
def on_edit_message(data):
    username = session.get('username')
    room_code = session.get('room_code')
    msg_id = data.get('id')
    new_content = data.get('content')
    if not username or not room_code or not msg_id or new_content is None:
        return
    # Encrypt new content
    enc_content = encrypt_message(new_content)
    update_message_edit(msg_id, enc_content)
    emit('message_edited', {'id': msg_id, 'content': new_content}, room=room_code)

@socketio.on('delete_message_both')
def on_delete_message_both(data):
    username = session.get('username')
    room_code = session.get('room_code')
    msg_id = data.get('id')
    if not username or not room_code or not msg_id:
        return
    delete_message_for_both(msg_id)
    emit('message_deleted_both', {'id': msg_id}, room=room_code)

@socketio.on('delete_message_self')
def on_delete_message_self(data):
    username = session.get('username')
    room_code = session.get('room_code')
    msg_id = data.get('id')
    if not username or not room_code or not msg_id:
        return
    delete_message_for_self(msg_id, username)
    emit('message_deleted_self', {'id': msg_id, 'username': username}, room=room_code)

@socketio.on('set_nickname')
def on_set_nickname(data):
    username = session.get('username')
    room_code = session.get('room_code')
    target = data.get('target')
    nickname = data.get('nickname')
    if not username or not room_code or not target or not nickname:
        return
    set_nickname(room_code, username, target, nickname)
    # Notify target user about nickname change
    emit('nickname_set', {'setter': username, 'target': target, 'nickname': nickname}, room=room_code)

@socketio.on('pin_message')
def on_pin_message(data):
    room_code = session.get('room_code')
    msg_id = data.get('id')
    if not room_code or not msg_id:
        return
    update_pinned_message(room_code, msg_id)
    emit('message_pinned', {'id': msg_id}, room=room_code)

@socketio.on('message_delivered')
def on_message_delivered(data):
    username = session.get('username')
    msg_id = data.get('message_id')
    room_code = session.get('room_code')
    if not username or not msg_id or not room_code:
        return
    save_message_status(msg_id, username, delivered=True)
    # Notify sender user(s)
    emit('message_delivered_update', {'message_id': msg_id, 'recipient': username}, room=room_code)

@socketio.on('message_read')
def on_message_read(data):
    username = session.get('username')
    room_code = session.get('room_code')
    last_read_id = data.get('last_read_message_id')
    if not username or not room_code or not last_read_id:
        return
    save_message_status(last_read_id, username, read=True)
    update_read_receipt(room_code, username, last_read_id)
    emit('message_read_update', {'message_id': last_read_id, 'reader': username}, room=room_code)

@socketio.on('search_messages')
def on_search_messages(data):
    room_code = session.get('room_code')
    query = data.get('query','').lower()
    if not room_code or not query:
        return
    c = db.cursor()
    c.execute('SELECT * FROM messages WHERE room_code=? AND deleted_for_both=0 ORDER BY timestamp DESC', (room_code,))
    results = []
    for r in c.fetchall():
        # decrypt message content and search in decrypted text
        try:
            text = decrypt_message(r['content']).lower()
        except:
            text = ""
        if query in text:
            results.append({
                'id': r['id'],
                'sender': r['sender'],
                'content': text,
                'timestamp': r['timestamp'],
                'type': r['message_type']
            })
    emit('search_results', results)

@socketio.on('get_media')
def on_get_media(data):
    room_code = session.get('room_code')
    media = get_all_media(room_code)
    # Decrypt content before sending
    for m in media:
        try:
            m['content'] = decrypt_message(m['content'])
        except:
            m['content'] = "[Error]"
    emit('media_list', media)

if __name__ == '__main__':
    socketio.run(app, debug=True)
    