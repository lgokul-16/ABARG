import os
from flask import Flask, request, jsonify, send_from_directory
from flask_jwt_extended import JWTManager, jwt_required, get_jwt_identity, create_access_token
from flask_socketio import SocketIO, join_room, emit
from flask_mail import Mail, Message as MailMessage
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import uuid
import secrets
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from supabase import create_client
from dotenv import load_dotenv

load_dotenv()

# === Supabase Setup ===
SUPABASE_URL = os.getenv("SUPABASE_URL", "").strip()
SUPABASE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "").strip()
if not SUPABASE_KEY:
    SUPABASE_KEY = os.getenv("SUPABASE_KEY", "").strip()
supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

# === Flask App ===
app = Flask(__name__, static_folder='.')
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key')
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'jwt-dev-secret')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("DATABASE_URL")

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Email config
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('EMAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('EMAIL_APP_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('EMAIL_USERNAME')

CORS(app, origins="*")



# === Database ===
db = SQLAlchemy(app)
mail = Mail(app)  # ✅ Initialize Flask-Mail

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    is_verified = db.Column(db.Boolean, default=False)
    profile_image = db.Column(db.String(255))

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class EmailOTP(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), nullable=False)
    otp = db.Column(db.String(6), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)

class Conversation(db.Model):
    id = db.Column(db.Integer, primary_key=True)

class Participant(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    conversation_id = db.Column(db.Integer, db.ForeignKey('conversation.id'))
    user_id = db.Column(db.Integer)

class Group(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    created_by = db.Column(db.Integer)

class GroupMember(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'))
    user_id = db.Column(db.Integer)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    conversation_id = db.Column(db.Integer, db.ForeignKey('conversation.id'))
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'))
    sender_id = db.Column(db.Integer)
    content = db.Column(db.Text)
    image_url = db.Column(db.String(255))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class Reaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    message_id = db.Column(db.Integer)
    user_id = db.Column(db.Integer)
    emoji = db.Column(db.String(10))

class FriendRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    from_user_id = db.Column(db.Integer)
    to_user_id = db.Column(db.Integer)
    status = db.Column(db.String(20), default='pending')

class Friend(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer)
    friend_id = db.Column(db.Integer)

# === Extensions ===
JWTManager(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")


# === Helper Functions ===
def send_otp_email(email, otp):
    msg = MailMessage(
        subject="Your ABARG OTP Code",
        recipients=[email],
        body=f"Your OTP code is: {otp}. It expires in 10 minutes."
    )
    try:
        mail.send(msg)
        print(f"✅ OTP sent to {email}")
    except Exception as e:
        print(f"❌ Email failed: {str(e)}")

# === Routes ===
@app.route('/')
def index():
    return send_from_directory('.', 'index.html')

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    if not username or not email or not password:
        return jsonify({"msg": "Missing fields"}), 400

    existing_user = User.query.filter_by(email=email).first()
    if existing_user:
        if existing_user.is_verified:
            return jsonify({"msg": "Email already registered"}), 400
        else:
            db.session.delete(existing_user)
            db.session.commit()

    if User.query.filter_by(username=username).first():
        return jsonify({"msg": "Username taken"}), 400

    user = User(username=username, email=email, is_verified=False)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()

    # Generate & send OTP
    otp = secrets.token_hex(3)[:6].upper()
    expires_at = datetime.utcnow() + timedelta(minutes=10)
    otp_record = EmailOTP(email=email, otp=otp, expires_at=expires_at)
    db.session.add(otp_record)
    db.session.commit()

    send_otp_email(email, otp)
    return jsonify({"msg": "User created. Check email for OTP."}), 201

@app.route('/verify-otp', methods=['POST'])
def verify_otp():
    data = request.get_json()
    email = data.get('email')
    otp = data.get('otp')
    if not email or not otp:
        return jsonify({"msg": "Email and OTP required"}), 400

    otp_record = EmailOTP.query.filter_by(email=email, otp=otp).first()
    if otp_record and datetime.utcnow() < otp_record.expires_at:
        user = User.query.filter_by(email=email).first()
        if user:
            user.is_verified = True
            db.session.delete(otp_record)
            db.session.commit()
            return jsonify({"msg": "Email verified!"}), 200

    return jsonify({"msg": "Invalid or expired OTP"}), 400

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    user = User.query.filter_by(email=email).first()
    if not user or not user.check_password(password):
        return jsonify({"msg": "Bad credentials"}), 401
    if not user.is_verified:
        return jsonify({"msg": "Email not verified"}), 403
    access_token = create_access_token(identity=str(user.id))
    return jsonify(access_token=access_token), 200

@app.route('/profile', methods=['GET'])
@jwt_required()
def profile():
    user_id = int(get_jwt_identity())
    user = User.query.get(user_id)
    return jsonify({
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "profile_image": user.profile_image
    })

@app.route('/friends', methods=['GET'])
@jwt_required()
def get_friends():
    user_id = int(get_jwt_identity())
    friends = db.session.query(User).join(Friend, Friend.friend_id == User.id).filter(
        Friend.user_id == user_id
    ).all()
    return jsonify([{
        "id": f.id,
        "username": f.username,
        "profile_image": f.profile_image
    } for f in friends])

@app.route('/conversation-with/<int:friend_id>', methods=['GET'])
@jwt_required()
def get_conversation_with(friend_id):
    user_id = int(get_jwt_identity())
    conv = db.session.query(Conversation).join(Participant).filter(
        Participant.user_id.in_([user_id, friend_id])
    ).group_by(Conversation.id).having(db.func.count(Participant.id) == 2).first()
    if not conv:
        conv = Conversation()
        db.session.add(conv)
        db.session.flush()
        p1 = Participant(conversation_id=conv.id, user_id=user_id)
        p2 = Participant(conversation_id=conv.id, user_id=friend_id)
        db.session.add_all([p1, p2])
        db.session.commit()
    return jsonify({"conversation_id": conv.id})

@app.route('/friend-requests/send', methods=['POST'])
@jwt_required()
def send_friend_request():
    user_id = int(get_jwt_identity())
    data = request.get_json()
    username = data.get('username')
    target = User.query.filter_by(username=username).first()
    if not target:
        return jsonify({"msg": "User not found"}), 404
    if target.id == user_id:
        return jsonify({"msg": "Cannot add yourself"}), 400
    existing = FriendRequest.query.filter(
        ((FriendRequest.from_user_id == user_id) & (FriendRequest.to_user_id == target.id)) |
        ((FriendRequest.from_user_id == target.id) & (FriendRequest.to_user_id == user_id))
    ).first()
    if existing:
        return jsonify({"msg": "Request already exists"}), 400
    req = FriendRequest(from_user_id=user_id, to_user_id=target.id)
    db.session.add(req)
    db.session.commit()
    return jsonify({"msg": "Friend request sent"}), 201

@app.route('/friend-requests/incoming', methods=['GET'])
@jwt_required()
def incoming_requests():
    user_id = int(get_jwt_identity())
    requests = FriendRequest.query.filter_by(to_user_id=user_id, status='pending').all()
    result = []
    for req in requests:
        sender = User.query.get(req.from_user_id)
        result.append({
            "request_id": req.id,
            "sender_id": sender.id,
            "username": sender.username
        })
    return jsonify(result), 200

@app.route('/friend-requests/<int:request_id>/accept', methods=['POST'])
@jwt_required()
def accept_friend_request(request_id):
    user_id = int(get_jwt_identity())
    req = FriendRequest.query.filter_by(id=request_id, to_user_id=user_id, status='pending').first_or_404()
    req.status = 'accepted'
    f1 = Friend(user_id=req.to_user_id, friend_id=req.from_user_id)
    f2 = Friend(user_id=req.from_user_id, friend_id=req.to_user_id)
    db.session.add_all([f1, f2])
    conv = Conversation()
    db.session.add(conv)
    db.session.flush()
    p1 = Participant(conversation_id=conv.id, user_id=req.to_user_id)
    p2 = Participant(conversation_id=conv.id, user_id=req.from_user_id)
    db.session.add_all([p1, p2])
    db.session.commit()
    return jsonify({"msg": "Friend added"}), 200

@app.route('/friend-requests/<int:request_id>/reject', methods=['POST'])
@jwt_required()
def reject_friend_request(request_id):
    user_id = int(get_jwt_identity())
    req = FriendRequest.query.filter_by(id=request_id, to_user_id=user_id, status='pending').first_or_404()
    req.status = 'rejected'
    db.session.commit()
    return jsonify({"msg": "Request rejected"}), 200

@app.route('/chat/history/<int:conversation_id>', methods=['GET'])
@jwt_required()
def chat_history(conversation_id):
    user_id = int(get_jwt_identity())
    participant = Participant.query.filter_by(conversation_id=conversation_id, user_id=user_id).first()
    if not participant:
        return jsonify({"msg": "Unauthorized"}), 403
    messages = Message.query.filter_by(conversation_id=conversation_id).order_by(Message.timestamp).all()
    result = []
    for m in messages:
        reactions = Reaction.query.filter_by(message_id=m.id).all()
        reaction_counts = {}
        for r in reactions:
            reaction_counts[r.emoji] = reaction_counts.get(r.emoji, 0) + 1
        sender = User.query.get(m.sender_id)
        result.append({
            "id": m.id,
            "sender_id": m.sender_id,
            "sender_name": sender.username if sender else "Unknown",
            "content": m.content,
            "image_url": m.image_url,
            "timestamp": m.timestamp.isoformat(),
            "reactions": reaction_counts
        })
    return jsonify(result), 200

@app.route('/chat/delete/<int:conversation_id>', methods=['DELETE'])
@jwt_required()
def delete_private_chat(conversation_id):
    user_id = int(get_jwt_identity())
    participant = Participant.query.filter_by(conversation_id=conversation_id, user_id=user_id).first()
    if not participant:
        return jsonify({"msg": "Unauthorized"}), 403
    Message.query.filter_by(conversation_id=conversation_id).delete()
    Reaction.query.filter(Reaction.message_id.in_(
        db.session.query(Message.id).filter_by(conversation_id=conversation_id)
    )).delete(synchronize_session=False)
    Participant.query.filter_by(conversation_id=conversation_id).delete()
    Conversation.query.filter_by(id=conversation_id).delete()
    db.session.commit()
    return jsonify({"msg": "Chat deleted"}), 200

@app.route('/group-chat/history/<int:group_id>', methods=['GET'])
@jwt_required()
def group_chat_history(group_id):
    user_id = int(get_jwt_identity())
    member = GroupMember.query.filter_by(group_id=group_id, user_id=user_id).first()
    if not member:
        return jsonify({"msg": "Unauthorized"}), 403
    messages = Message.query.filter_by(group_id=group_id).order_by(Message.timestamp).all()
    result = []
    for m in messages:
        reactions = Reaction.query.filter_by(message_id=m.id).all()
        reaction_counts = {}
        for r in reactions:
            reaction_counts[r.emoji] = reaction_counts.get(r.emoji, 0) + 1
        sender = User.query.get(m.sender_id)
        result.append({
            "id": m.id,
            "sender_id": m.sender_id,
            "sender_name": sender.username if sender else "Unknown",
            "content": m.content,
            "image_url": m.image_url,
            "timestamp": m.timestamp.isoformat(),
            "reactions": reaction_counts
        })
    return jsonify(result), 200

@app.route('/groups/<int:group_id>/delete', methods=['DELETE'])
@jwt_required()
def delete_group(group_id):
    user_id = int(get_jwt_identity())
    group = Group.query.get_or_404(group_id)
    if group.created_by != user_id:
        return jsonify({"msg": "Only group creator can delete this group"}), 403
    Message.query.filter_by(group_id=group_id).delete()
    Reaction.query.filter(Reaction.message_id.in_(
        db.session.query(Message.id).filter_by(group_id=group_id)
    )).delete(synchronize_session=False)
    GroupMember.query.filter_by(group_id=group_id).delete()
    Group.query.filter_by(id=group_id).delete()
    db.session.commit()
    return jsonify({"msg": "Group deleted"}), 200

@app.route('/upload-image', methods=['POST'])
@jwt_required()
def upload_image():
    if 'image' not in request.files:
        return jsonify({"msg": "No image"}), 400
    file = request.files['image']
    filename = secure_filename(file.filename)
    ext = filename.split('.')[-1].lower()
    if ext not in ['png', 'jpg', 'jpeg', 'gif', 'webp']:
        return jsonify({"msg": "Invalid image type"}), 400
    new_filename = f"{uuid.uuid4().hex}.{ext}"
    try:
        supabase.storage.from_("uploads").upload(
            path=new_filename,
            file=file.read(),
            file_options={"content-type": file.mimetype}
        )
        url = f"{SUPABASE_URL}/storage/v1/object/public/uploads/{new_filename}"
        return jsonify({"url": url}), 201
    except Exception as e:
        print(f"Upload error: {str(e)}")
        return jsonify({"msg": "Upload failed"}), 500

@app.route('/groups/create', methods=['POST'])
@jwt_required()
def create_group():
    user_id = int(get_jwt_identity())
    data = request.get_json()
    group_name = data.get('group_name')
    member_ids = data.get('member_ids', [])
    if not group_name:
        return jsonify({"msg": "Group name required"}), 400
    group = Group(name=group_name, created_by=user_id)
    db.session.add(group)
    db.session.flush()
    creator_member = GroupMember(group_id=group.id, user_id=user_id)
    db.session.add(creator_member)
    for member_id in member_ids:
        if member_id != user_id:
            member = GroupMember(group_id=group.id, user_id=member_id)
            db.session.add(member)
    db.session.commit()
    return jsonify({
        "msg": "Group created successfully",
        "group_id": group.id,
        "group_name": group.name
    }), 201

@app.route('/groups', methods=['GET'])
@jwt_required()
def get_groups():
    user_id = int(get_jwt_identity())
    groups = db.session.query(Group).join(GroupMember).filter(
        GroupMember.user_id == user_id
    ).all()
    result = []
    for group in groups:
        member_count = GroupMember.query.filter_by(group_id=group.id).count()
        result.append({
            "id": group.id,
            "name": group.name,
            "member_count": member_count,
            "created_by": group.created_by
        })
    return jsonify(result), 200

@app.route('/groups/<int:group_id>/members', methods=['GET'])
@jwt_required()
def get_group_members(group_id):
    user_id = int(get_jwt_identity())
    member = GroupMember.query.filter_by(group_id=group_id, user_id=user_id).first()
    if not member:
        return jsonify({"msg": "Unauthorized"}), 403
    members = db.session.query(User).join(GroupMember).filter(
        GroupMember.group_id == group_id
    ).all()
    result = []
    for member in members:
        result.append({
            "id": member.id,
            "username": member.username,
            "profile_image": member.profile_image
        })
    return jsonify(result), 200

@app.route('/profile/upload-dp', methods=['POST'])
@jwt_required()
def upload_profile_dp():
    user_id = int(get_jwt_identity())
    if 'image' not in request.files:
        return jsonify({"msg": "No image"}), 400
    file = request.files['image']
    filename = secure_filename(file.filename)
    ext = filename.split('.')[-1].lower()
    if ext not in ['png', 'jpg', 'jpeg', 'webp']:
        return jsonify({"msg": "Invalid image type"}), 400
    new_filename = f"profile_{user_id}_{uuid.uuid4().hex}.{ext}"
    try:
        supabase.storage.from_("uploads").upload(
            path=new_filename,
            file=file.read(),
            file_options={"content-type": file.mimetype}
        )
        url = f"{SUPABASE_URL}/storage/v1/object/public/uploads/{new_filename}"
        user = User.query.get(user_id)
        user.profile_image = url
        db.session.commit()
        return jsonify({"url": url}), 200
    except Exception as e:
        print(f"Profile upload error: {str(e)}")
        return jsonify({"msg": "Upload failed"}), 500

# === Socket.IO Events ===
user_sessions = {}

@socketio.on('connect')
def handle_connect():
    token = request.args.get('token')
    if not token:
        return False
    try:
        from flask_jwt_extended import decode_token
        decoded = decode_token(token)
        user_id = int(decoded['sub'])
        user_sessions[request.sid] = user_id
        return True
    except Exception as e:
        print(f"Socket auth failed: {e}")
        return False

@socketio.on('disconnect')
def handle_disconnect():
    user_id = user_sessions.pop(request.sid, None)

def get_user_id():
    return user_sessions.get(request.sid)

def is_participant(conversation_id, user_id):
    return Participant.query.filter_by(conversation_id=conversation_id, user_id=user_id).first() is not None

def is_group_member(group_id, user_id):
    return GroupMember.query.filter_by(group_id=group_id, user_id=user_id).first() is not None

@socketio.on('join_private_chat')
def handle_join_private(data):
    user_id = get_user_id()
    if not user_id:
        emit('error', {'msg': 'Authentication required'})
        return
    conversation_id = data['conversation_id']
    if not is_participant(conversation_id, user_id):
        emit('error', {'msg': 'Not authorized'})
        return
    join_room(f'private_{conversation_id}')

@socketio.on('join_group_chat')
def handle_join_group(data):
    user_id = get_user_id()
    if not user_id:
        emit('error', {'msg': 'Authentication required'})
        return
    group_id = data['group_id']
    if not is_group_member(group_id, user_id):
        emit('error', {'msg': 'Not authorized'})
        return
    join_room(f'group_{group_id}')

@socketio.on('send_message')
def handle_message(data):
    user_id = get_user_id()
    if not user_id:
        emit('error', {'msg': 'Authentication required'})
        return
    content = data.get('content', '')
    image_url = data.get('image_url')
    conversation_id = data.get('conversation_id')
    group_id = data.get('group_id')
    if not content and not image_url:
        emit('error', {'msg': 'Empty message'})
        return
    msg = Message(sender_id=user_id, content=content, image_url=image_url)
    if conversation_id:
        if not is_participant(conversation_id, user_id):
            emit('error', {'msg': 'Not authorized'})
            return
        msg.conversation_id = conversation_id
        room = f'private_{conversation_id}'
        event = 'new_message'
    elif group_id:
        if not is_group_member(group_id, user_id):
            emit('error', {'msg': 'Not authorized'})
            return
        msg.group_id = group_id
        room = f'group_{group_id}'
        event = 'new_group_message'
    else:
        emit('error', {'msg': 'Invalid chat type'})
        return
    db.session.add(msg)
    db.session.commit()
    sender = User.query.get(user_id)
    emit(event, {
        'id': msg.id,
        'sender_id': msg.sender_id,
        'sender_name': sender.username if sender else "Unknown",
        'content': msg.content,
        'image_url': msg.image_url,
        'timestamp': msg.timestamp.isoformat(),
        'reactions': {}
    }, room=room)

@socketio.on('react')
def handle_reaction(data):
    user_id = get_user_id()
    if not user_id:
        emit('error', {'msg': 'Authentication required'})
        return
    message_id = data['message_id']
    emoji = data['emoji']
    msg = Message.query.get(message_id)
    if not msg:
        emit('error', {'msg': 'Message not found'})
        return
    if msg.conversation_id and not is_participant(msg.conversation_id, user_id):
        emit('error', {'msg': 'Not authorized'})
        return
    if msg.group_id and not is_group_member(msg.group_id, user_id):
        emit('error', {'msg': 'Not authorized'})
        return
    existing = Reaction.query.filter_by(message_id=message_id, user_id=user_id).first()
    if existing:
        existing.emoji = emoji
    else:
        new_reaction = Reaction(message_id=message_id, user_id=user_id, emoji=emoji)
        db.session.add(new_reaction)
    db.session.commit()
    reactions = Reaction.query.filter_by(message_id=message_id).all()
    reaction_counts = {}
    for r in reactions:
        reaction_counts[r.emoji] = reaction_counts.get(r.emoji, 0) + 1
    if msg.conversation_id:
        room = f'private_{msg.conversation_id}'
    else:
        room = f'group_{msg.group_id}'
    emit('reaction_update', {
        'message_id': message_id,
        'reactions': reaction_counts
    }, room=room)

# === Run ===
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    socketio.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=True)