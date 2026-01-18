import eventlet
eventlet.monkey_patch()

import os
import uuid
from datetime import datetime
from flask import Flask, request, jsonify, send_from_directory
from flask_jwt_extended import JWTManager, jwt_required, get_jwt_identity, create_access_token
from flask_socketio import SocketIO, join_room, emit
from flask_mail import Mail, Message as MailMessage
from werkzeug.utils import secure_filename
from flask_cors import CORS
from supabase import create_client
from werkzeug.middleware.proxy_fix import ProxyFix

# Import Config
from config import Config
# Import DB and Models from models.py
from models import db, User, EmailOTP, Conversation, Participant, Group, GroupMember, Message, Reaction, FriendRequest, \
    Friend

# === Flask App Setup ===
app = Flask(__name__, static_folder='.')
app.config.from_object(Config)

# Fix for proxy headers (required for Railway/Https)
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)
app.config['UPLOAD_FOLDER'] = 'uploads'

# Initialize Extensions
CORS(app, origins="*")
mail = Mail(app)
JWTManager(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# Initialize DB with App
db.init_app(app)

# Create Tables
with app.app_context():
    db.create_all()

# === Supabase Client ===
supabase = create_client(app.config['SUPABASE_URL'], app.config['SUPABASE_KEY'])


# === Helper Functions ===
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS



def send_otp_email(email, otp):
    print(f"DEBUG OTP for {email}: {otp}")
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


def upload_file_helper(file, subfolder="uploads"):
    """
    Attempts to upload to Supabase. Falls back to local storage on failure.
    Returns the public URL.
    """
    filename = secure_filename(file.filename)
    new_filename = f"{uuid.uuid4().hex}_{filename}"
    
    # ensure local folder exists
    local_folder = app.config['UPLOAD_FOLDER']
    if not os.path.exists(local_folder):
        os.makedirs(local_folder)

    try:
        # Try Supabase
        # Supabase path often has no leading slash for 'upload', but bucket is 'uploads'
        path_on_supa = new_filename
        
        file_content = file.read()
        file.seek(0) # Reset for local save if needed

        supabase.storage.from_("uploads").upload(
            path=path_on_supa,
            file=file_content,
            file_options={"content-type": file.mimetype}
        )
        
        # Construct URL
        # Ensure trailing slash logic in config doesn't double slash if already correct,
        # but supabase_url usually is base. 
        # Easier: use get_public_url if available or manual construction
        # Manual construction seems consistent with existing code
        supa_url = app.config['SUPABASE_URL'].rstrip('/')
        url = f"{supa_url}/storage/v1/object/public/uploads/{path_on_supa}"
        return url

    except Exception as e:
        print(f"⚠️ Supabase Upload Failed ({str(e)}). Falling back to local storage.")
        
        # Fallback to local
        file.seek(0)
        local_path = os.path.join(local_folder, new_filename)
        file.save(local_path)
        
        # Generate local URL
        from flask import url_for
        return url_for('uploaded_file', filename=new_filename, _external=True)


# === Routes ===
@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/')
def index():
    return send_from_directory('.', 'index.html')


@app.route('/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')

        if not username or not email or not password:
            return jsonify({"msg": "Missing fields"}), 400

        # Cleanup unverified users
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            if existing_user.is_verified:
                return jsonify({"msg": "Email already registered"}), 400
            else:
                db.session.delete(existing_user)
                db.session.commit()

        if User.query.filter_by(username=username).first():
            return jsonify({"msg": "Username taken"}), 400

        # Auto-verify to bypass email issues
        user = User(username=username, email=email, is_verified=True)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        # Generate & send OTP (SKIPPED)
        # try:
        #    otp = EmailOTP.create_otp(email)
        #    send_otp_email(email, otp)
        # except Exception as e:
        #    print(f"OTP Error: {e}")
        #    pass

        return jsonify({"msg": "User created and verified automatically. Please Login."}), 201
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"msg": f"Server Error: {str(e)}"}), 500


@app.route('/verify-otp', methods=['POST'])
def verify_otp():
    try:
        data = request.get_json()
        email = data.get('email')
        otp = data.get('otp')

        if not email or not otp:
            return jsonify({"msg": "Email and OTP required"}), 400

        if EmailOTP.verify_otp(email, otp):
            user = User.query.filter_by(email=email).first()
            if user:
                user.is_verified = True
                db.session.commit()
                return jsonify({"msg": "Email verified!"}), 200

        return jsonify({"msg": "Invalid or expired OTP"}), 400
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"msg": f"Server Error details: {str(e)}"}), 500


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    user = User.query.filter_by(email=email).first()
    if not user or not user.check_password(password):
        return jsonify({"msg": "Bad credentials"}), 401
    
    # Auto-allow login (Verification disabled)
    # if not user.is_verified:
    #    return jsonify({"msg": "Email not verified"}), 403

    access_token = create_access_token(identity=str(user.id))
    return jsonify(access_token=access_token), 200

# EMERGENCY RESET ROUTE
@app.route('/reset-db-emergency', methods=['GET'])
def reset_db():
    try:
        db.drop_all()
        db.create_all()
        return "Database Wiped and Recreated. You can now register from scratch.", 200
    except Exception as e:
        return f"Error: {e}", 500


@app.route('/profile', methods=['GET'])
@jwt_required()
def profile():
    user_id = int(get_jwt_identity())
    user = db.session.get(User, user_id)
    return jsonify({
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "profile_image": user.profile_image,
        "description": user.description
    }), 200


@app.route('/profile/update', methods=['POST'])
@jwt_required()
def update_profile():
    try:
        user_id = int(get_jwt_identity())
        user = db.session.get(User, user_id)
        data = request.get_json()
        
        if 'description' in data:
            user.description = data['description']
        
        db.session.commit()
        return jsonify({"msg": "Profile updated"}), 200
    except Exception as e:
        print(f"Update Profile Error: {e}")
        return jsonify({"msg": f"Server error: {str(e)}"}), 500


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
        "profile_image": f.profile_image,
        "description": f.description
    } for f in friends])


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
        group_mem = GroupMember.query.filter_by(group_id=group_id, user_id=member.id).first()
        dp = group_mem.custom_profile_image if group_mem.custom_profile_image else member.profile_image
        result.append({
            "id": member.id,
            "username": member.username,
            "profile_image": dp,
            "role": group_mem.role,
            "description": member.description
        })
    return jsonify(result), 200


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
        sender = db.session.get(User, req.from_user_id)
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

    # Create conversation immediately
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


@app.route('/groups/<int:group_id>/upload-icon', methods=['POST'])
@jwt_required()
def upload_group_icon(group_id):
    try:
        user_id = int(get_jwt_identity())
        group_member = GroupMember.query.filter_by(group_id=group_id, user_id=user_id).first()

        if not group_member or group_member.role != 'admin':
            return jsonify({"msg": "Admins only"}), 403

        if 'image' not in request.files:
            return jsonify({"msg": "No image part"}), 400
        file = request.files['image']
        if file.filename == '':
            return jsonify({"msg": "No selected file"}), 400

        if file and allowed_file(file.filename):
            try:
                final_url = upload_file_helper(file)
                
                # Update Group
                group = db.session.get(Group, group_id)
                group.image_url = final_url
                db.session.commit()
                
                return jsonify({"msg": "Group icon updated", "url": final_url}), 200
            except Exception as e:
                print(f"Group Icon Upload Critical Error: {e}")
                import traceback
                traceback.print_exc()
                return jsonify({"msg": f"Server error: {str(e)}"}), 500

        return jsonify({"msg": "Invalid file type"}), 400
    except Exception as e:
        print(f"Group Icon Upload Error: {e}")
        return jsonify({"msg": f"Server error: {str(e)}"}), 500


@app.route('/chat/history/<int:conversation_id>', methods=['GET'])
@jwt_required()
def chat_history(conversation_id):
    user_id = int(get_jwt_identity())
    participant = Participant.query.filter_by(conversation_id=conversation_id, user_id=user_id).first()
    if not participant:
        return jsonify({"msg": "Unauthorized"}), 403

    
    # Filter expired messages
    now = datetime.utcnow()
    messages = Message.query.filter(
        Message.conversation_id == conversation_id,
        (Message.expires_at == None) | (Message.expires_at > now)
    ).order_by(Message.timestamp).all()
    # Fetch contextual DPs for all participants
    participants = Participant.query.filter_by(conversation_id=conversation_id).all()
    user_dps = {}
    for p in participants:
        user = db.session.get(User, p.user_id)
        user_dps[p.user_id] = p.custom_profile_image if p.custom_profile_image else user.profile_image

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
            "sender_dp": user_dps.get(m.sender_id),
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

    # Bulk delete reactions for these messages (Complex query simplified for SQLite/Postgres compatibility)
    # Ideally, use CASCADE in DB. Here manual:
    # Reaction delete logic is complex without CASCADE, skipping strict cleanup for speed or assume DB handles it

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

    
    # Filter expired messages
    now = datetime.utcnow()
    messages = Message.query.filter(
        Message.group_id == group_id,
        (Message.expires_at == None) | (Message.expires_at > now)
    ).order_by(Message.timestamp).all()
    # Fetch contextual DPs
    members = GroupMember.query.filter_by(group_id=group_id).all()
    user_dps = {}
    user_dps = {}
    for m in members:
        user = db.session.get(User, m.user_id)
        if user:
            user_dps[m.user_id] = m.custom_profile_image if m.custom_profile_image else user.profile_image

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
            "sender_dp": user_dps.get(m.sender_id),
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
    group = db.session.get(Group, group_id)
    if not group:
        return jsonify({"msg": "Group not found"}), 404
    if group.created_by != user_id:
        return jsonify({"msg": "Only group creator can delete this group"}), 403

    Message.query.filter_by(group_id=group_id).delete()
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

    try:
        url = upload_file_helper(file)
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

    # Creator is always admin
    creator_member = GroupMember(group_id=group.id, user_id=user_id, role='admin')
    db.session.add(creator_member)

    for member_id in member_ids:
        if member_id != user_id:
            # Verify they are friends
            is_friend = Friend.query.filter(
                ((Friend.user_id == user_id) & (Friend.friend_id == member_id)) |
                ((Friend.user_id == member_id) & (Friend.friend_id == user_id))
            ).first()
            
            if is_friend:
                member = GroupMember(group_id=group.id, user_id=member_id, role='member')
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
            "image_url": group.image_url,
            "member_count": member_count,
            "created_by": group.created_by
        })
    return jsonify(result), 200





@app.route('/groups/<int:group_id>/promote', methods=['POST'])
@jwt_required()
def promote_member(group_id):
    user_id = int(get_jwt_identity())
    target_id = request.json.get('user_id')
    
    requester = GroupMember.query.filter_by(group_id=group_id, user_id=user_id).first()
    if not requester or requester.role != 'admin':
        return jsonify({"msg": "Admin privileges required"}), 403

    target = GroupMember.query.filter_by(group_id=group_id, user_id=target_id).first()
    if target:
        target.role = 'admin'
        db.session.commit()
        return jsonify({"msg": "Member promoted"}), 200
    return jsonify({"msg": "Member not found"}), 404


@app.route('/groups/<int:group_id>/demote', methods=['POST'])
@jwt_required()
def demote_member(group_id):
    user_id = int(get_jwt_identity())
    target_id = request.json.get('user_id')
    
    group = Group.query.get(group_id)
    if group.created_by != user_id:
        return jsonify({"msg": "Only group creator can demote admins"}), 403

    target = GroupMember.query.filter_by(group_id=group_id, user_id=target_id).first()
    if target:
        target.role = 'member'
        db.session.commit()
        return jsonify({"msg": "Member demoted"}), 200
    return jsonify({"msg": "Member not found"}), 404


@app.route('/groups/<int:group_id>/kick', methods=['POST'])
@jwt_required()
def kick_member(group_id):
    user_id = int(get_jwt_identity())
    target_id = request.json.get('user_id')
    
    requester = GroupMember.query.filter_by(group_id=group_id, user_id=user_id).first()
    if not requester or requester.role != 'admin':
        return jsonify({"msg": "Admin privileges required"}), 403

    # Prevent kicking creator
    group = db.session.get(Group, group_id)
    if target_id == group.created_by:
        return jsonify({"msg": "Cannot kick the creator"}), 400

    GroupMember.query.filter_by(group_id=group_id, user_id=target_id).delete()
    db.session.commit()
    
    # Notify via socket? For now just API response
    return jsonify({"msg": "Member kicked"}), 200


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

    try:
        url = upload_file_helper(file)
        
        user = db.session.get(User, user_id)
        user.profile_image = url
        db.session.commit()
        return jsonify({"url": url}), 200
    except Exception as e:
        print(f"Profile upload error: {str(e)}")
        return jsonify({"msg": "Upload failed"}), 500


@app.route('/chat/<string:chat_type>/<int:chat_id>/upload-dp', methods=['POST'])
@jwt_required()
def upload_contextual_dp(chat_type, chat_id):
    user_id = int(get_jwt_identity())
    if 'image' not in request.files:
        return jsonify({"msg": "No image"}), 400
    file = request.files['image']
    filename = secure_filename(file.filename)
    ext = filename.split('.')[-1].lower()

    if ext not in ['png', 'jpg', 'jpeg', 'webp']:
        return jsonify({"msg": "Invalid image type"}), 400

    try:
        url = upload_file_helper(file)
        
        if chat_type == 'private':
            # Update Participant
            participant = Participant.query.filter_by(conversation_id=chat_id, user_id=user_id).first()
            if not participant:
                return jsonify({"msg": "Unauthorized"}), 403
            participant.custom_profile_image = url
        elif chat_type == 'group':
            # Update GroupMember
            member = GroupMember.query.filter_by(group_id=chat_id, user_id=user_id).first()
            if not member:
                return jsonify({"msg": "Unauthorized"}), 403
            member.custom_profile_image = url
        else:
            return jsonify({"msg": "Invalid chat type"}), 400

        db.session.commit()
        return jsonify({"url": url}), 200
    except Exception as e:
        print(f"Contextual DP upload error: {str(e)}")
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


@socketio.on('join_private_chat')
def handle_join_private(data):
    user_id = get_user_id()
    if not user_id:
        emit('error', {'msg': 'Authentication required'})
        return
    conversation_id = data['conversation_id']

    # Verify participation
    if not Participant.query.filter_by(conversation_id=conversation_id, user_id=user_id).first():
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

    # Verify membership
    if not GroupMember.query.filter_by(group_id=group_id, user_id=user_id).first():
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
    lifespan = data.get('lifespan')  # seconds
    client_temp_id = data.get('client_temp_id') # Optimistic UI

    if not content and not image_url:
        emit('error', {'msg': 'Empty message'})
        return

    msg = Message(sender_id=user_id, content=content, image_url=image_url)
    
    if lifespan:
        from datetime import timedelta
        msg.expires_at = datetime.utcnow() + timedelta(seconds=int(lifespan))

    if conversation_id:
        if not Participant.query.filter_by(conversation_id=conversation_id, user_id=user_id).first():
            emit('error', {'msg': 'Not authorized'})
            return
        msg.conversation_id = conversation_id
        room = f'private_{conversation_id}'
        event = 'new_message'
    elif group_id:
        if not GroupMember.query.filter_by(group_id=group_id, user_id=user_id).first():
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

    # Determine sender_dp contextual to the chat
    sender_dp = None
    sender = db.session.get(User, user_id)
    sender_name = sender.username if sender else "Unknown" 
    
    if msg.group_id:
        # Fetch group member profile
        member = GroupMember.query.filter_by(group_id=msg.group_id, user_id=user_id).first()
        if member:
            sender_dp = member.custom_profile_image if member.custom_profile_image else sender.profile_image
            # Also use admin role badge if needed, but handled in frontend usually.
            # Ideally frontend needs 'role' or we append it to name?
            # Start simple: correct DP.
        else:
            sender_dp = sender.profile_image
    elif msg.conversation_id:
        # Private chat member profile
        part = Participant.query.filter_by(conversation_id=msg.conversation_id, user_id=user_id).first()
        sender_dp = part.custom_profile_image if part and part.custom_profile_image else sender.profile_image
    else:
        sender_dp = sender.profile_image

    emit(event, {
        'id': msg.id,
        'client_temp_id': client_temp_id,
        'sender_id': msg.sender_id,
        'sender_name': sender_name,
        'sender_dp': sender_dp,
        'content': msg.content,
        'image_url': msg.image_url,
        'timestamp': msg.timestamp.isoformat(),
        'reactions': {}
    }, room=room)


@app.route('/cleanup-reactions', methods=['GET'])
def cleanup_reactions():
    from sqlalchemy import text
    try:
        # Delete entries that are duplicates (not the MAX id for that user+msg combo)
        db.session.execute(text("""
            DELETE FROM reaction 
            WHERE id NOT IN (
                SELECT MAX(id) 
                FROM reaction 
                GROUP BY message_id, user_id
            )
        """))
        db.session.commit()
        return "Cleaned up duplicates successfully. Emojis should now show correctly.", 200
    except Exception as e:
        print(f"Cleanup Error: {e}")
        return f"Error: {str(e)}", 500

@socketio.on('react')
def handle_reaction(data):
    try:
        user_id = get_user_id()
        if not user_id:
            return

        # Explicitly cast to int to avoid room mismatch or DB issues
        message_id = int(data.get('message_id'))
        emoji = str(data.get('emoji'))
        
        msg = db.session.get(Message, message_id)
        if not msg:
            return

        # Determine Room and Auth
        room = None
        if msg.conversation_id:
            # Check if user is in this conversation
            is_part = db.session.query(Participant).filter_by(
                conversation_id=msg.conversation_id, user_id=user_id
            ).first()
            if is_part:
                room = f'private_{msg.conversation_id}'
        elif msg.group_id:
            # Check if user is in this group
            is_mem = db.session.query(GroupMember).filter_by(
                group_id=msg.group_id, user_id=user_id
            ).first()
            if is_mem:
                room = f'group_{msg.group_id}'

        if not room:
            print(f"Socket React: User {user_id} not authorized for msg {message_id}")
            return

        # Update or Insert
        existing = db.session.query(Reaction).filter_by(
            message_id=message_id, user_id=user_id
        ).first()
        
        if existing:
            existing.emoji = emoji
        else:
            db.session.add(Reaction(message_id=message_id, user_id=user_id, emoji=emoji))
        
        db.session.commit()

        # Get updated counts for exactly this message
        rows = db.session.query(Reaction.emoji, db.func.count(Reaction.id)).filter_by(
            message_id=message_id
        ).group_by(Reaction.emoji).all()
        
        reaction_counts = {row[0]: row[1] for row in rows}

        print(f"Broadcasting reaction to {room}: {reaction_counts}")
        emit('reaction_update', {
            'message_id': message_id,
            'reactions': reaction_counts
        }, room=room)
        
    except Exception as e:
        print(f"Reaction Error: {e}")
        db.session.rollback()

# === Run ===
if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))