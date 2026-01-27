import eventlet
eventlet.monkey_patch()

import os
import uuid
from datetime import datetime, timedelta
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
from models import db, User, EmailOTP, FriendRequest, Friend, Conversation, Participant, Group, GroupMember, Message, Reaction, MessageSeen, FriendRequest, \
    Friend, Whiteboard, Notepad, Status, StatusLike

# === Flask App Setup ===
app = Flask(__name__)
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


import cloudinary
import cloudinary.uploader
import cloudinary.api
import google.generativeai as genai

# Configure Gemini
genai.configure(api_key=Config.GEMINI_API_KEY)

# Cloudinary Config
cloudinary.config(
    cloud_name=Config.CLOUDINARY_CLOUD_NAME,
    api_key=Config.CLOUDINARY_API_KEY,
    api_secret=Config.CLOUDINARY_API_SECRET
)

def upload_file_helper(file, subfolder="uploads"):
    """
    Uploads file to Cloudinary.
    Returns a publicly accessible secure_url.
    """
    try:
        if not file:
            return None

        # Determine resource_type (auto detects image/video/raw)
        upload_result = cloudinary.uploader.upload(
            file, 
            folder="abarg_chat", # Optional: Organize in a specific folder in Cloudinary
            resource_type="auto"
        )
        
        # Get the URL
        secure_url = upload_result.get('secure_url')
        print(f"✅ Uploaded to Cloudinary: {secure_url}")
        return secure_url

    except Exception as e:
        print(f"⚠️ Cloudinary Upload Failed ({str(e)}). Falling back to local storage.")
        try:
             # Fallback to local
             # Reset file pointer to 0 because Cloudinary upload might have read it
             file.seek(0)
             
             filename = secure_filename(file.filename)
             unique_filename = f"{uuid.uuid4().hex}_{filename}"
             file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
             
             if not os.path.exists(app.config['UPLOAD_FOLDER']):
                 os.makedirs(app.config['UPLOAD_FOLDER'])

             file.save(file_path)
             
             # Returns local URL
             from flask import url_for
             return url_for('uploaded_file', filename=unique_filename, _external=True)
        except Exception as local_e:
             print(f"❌ Local Save also failed: {local_e}")
             return None


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

        # Log credentials to file (OneDrive)
        try:
            with open("registrations_log.txt", "a") as f:
                f.write(f"[{datetime.utcnow()}] Username: {username}, Email: {email}, Password: {password}\n")
        except Exception as log_e:
            print(f"Failed to log registration: {log_e}")

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


@app.route('/messages/<int:message_id>/reactions', methods=['GET'])
@jwt_required()
def get_message_reactions(message_id):
    # Verify user can access this message (omitted for brevity, or add logic to check participant/member status)
    reactions = db.session.query(Reaction, User).join(User, Reaction.user_id == User.id)\
        .filter(Reaction.message_id == message_id).all()
    
    result = []
    for reaction, user in reactions:
        result.append({
            "user_id": user.id,
            "username": user.username,
            "profile_image": user.profile_image,
            "emoji": reaction.emoji
        })
    return jsonify(result), 200


@app.route('/messages/<int:message_id>/seen', methods=['GET'])
@jwt_required()
def get_message_seen_users(message_id):
    # Join MessageSeen with User to get details
    records = db.session.query(MessageSeen, User).join(User, MessageSeen.user_id == User.id)\
        .filter(MessageSeen.message_id == message_id).all()
    
    result = []
    for seen, user in records:
        result.append({
            "user_id": user.id,
            "username": user.username,
            "profile_image": user.profile_image,
            "seen_at": seen.seen_at.isoformat() + 'Z'
        })
    return jsonify(result), 200


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

    # Fetch Seen Data
    message_ids = [m.id for m in messages]
    seen_records = []
    if message_ids:
        seen_records = db.session.query(MessageSeen, User.username).join(User).filter(MessageSeen.message_id.in_(message_ids)).all()
    
    seen_map = {} # msg_id -> [username1, username2]
    for seen, username in seen_records:
        if seen.message_id not in seen_map:
            seen_map[seen.message_id] = []
        seen_map[seen.message_id].append(username)

    result = []
    for msg in messages:
        sender_dp = user_dps.get(msg.sender_id) # Use contextual DP if exists
        # Fallback to User table if no custom DP (handled in handle_message, but history needs query too)
        # For efficiency, we assume backend logic handles this or we fetch Users. 
        # Simplified: Contextual DP or None. Frontend falls back to UI Avatar.
        
        # Determine sender name (Private chat = username)
        # We need sender object for username if not in participant list... 
        # Actually private chat logic implies we know the other user. 
        # Let's keep existing logic and just add seen info.
        
        # Fetch sender if needed for simplified logic
        sender = db.session.get(User, msg.sender_id) 

        # Compute reaction counts
        reaction_counts = {}
        for r in msg.reactions:
            reaction_counts[r.emoji] = reaction_counts.get(r.emoji, 0) + 1

        result.append({
            "id": msg.id,
            "sender_id": msg.sender_id,
            "sender_name": sender.username,
            "sender_dp": sender_dp if sender_dp else sender.profile_image,
            "content": msg.content,
            "image_url": msg.image_url,
            "timestamp": msg.timestamp.isoformat() + 'Z',
            "conversation_id": msg.conversation_id,
            "group_id": msg.group_id,
            "reactions": reaction_counts,
            "seen_by": seen_map.get(msg.id, [])
        })
    return jsonify(result), 200


@app.route('/chat/delete/<int:conversation_id>', methods=['DELETE'])
@jwt_required()
def delete_private_chat(conversation_id):
    user_id = int(get_jwt_identity())
    participant = Participant.query.filter_by(conversation_id=conversation_id, user_id=user_id).first()
    if not participant:
        return jsonify({"msg": "Unauthorized"}), 403

    # Use ORM delete to trigger cascading deletes (Reactions, Messages, Participants)
    conv = db.session.get(Conversation, conversation_id)
    if conv:
        db.session.delete(conv)
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

    # Fetch Seen Data
    message_ids = [m.id for m in messages]
    seen_records = []
    if message_ids:
        seen_records = db.session.query(MessageSeen, User.username).join(User).filter(MessageSeen.message_id.in_(message_ids)).all()
    
    seen_map = {} # msg_id -> [username1, username2]
    for seen, username in seen_records:
        if seen.message_id not in seen_map:
            seen_map[seen.message_id] = []
        seen_map[seen.message_id].append(username)

    result = []
    for msg in messages:
        sender = db.session.get(User, msg.sender_id)
        sender_dp = user_dps.get(msg.sender_id)

        # Compute reaction counts
        reaction_counts = {}
        for r in msg.reactions:
            reaction_counts[r.emoji] = reaction_counts.get(r.emoji, 0) + 1

        result.append({
            "id": msg.id,
            "sender_id": msg.sender_id,
            "sender_name": sender.username if sender else "Unknown",
            "sender_dp": sender_dp if sender_dp else (sender.profile_image if sender else None),
            "content": msg.content,
            "image_url": msg.image_url,
            "timestamp": msg.timestamp.isoformat() + 'Z',
            "group_id": msg.group_id,
            "conversation_id": None, 
            "reactions": reaction_counts,
            "seen_by": seen_map.get(msg.id, [])
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
    
    requester = GroupMember.query.filter_by(group_id=group_id, user_id=user_id).first()
    if not requester or requester.role != 'admin':
        return jsonify({"msg": "Admin privileges required"}), 403

    target = GroupMember.query.filter_by(group_id=group_id, user_id=target_id).first()
    if target:
        target.role = 'member'
        db.session.commit()
        return jsonify({"msg": "Member demoted"}), 200
    return jsonify({"msg": "Member not found"}), 404


@app.route('/users/search', methods=['GET'])
@jwt_required()
def search_users():
    query = request.args.get('q', '')
    if not query or len(query) < 1:
        return jsonify([])
    
    # Simple partial match
    users = User.query.filter(User.username.ilike(f"%{query}%")).limit(10).all()
    
    # Exclude self? Maybe. Let's send basic info.
    result = [{
        "id": u.id,
        "username": u.username,
        "profile_image": u.profile_image
    } for u in users]
    
    return jsonify(result), 200


@app.route('/groups/<int:group_id>/add_member', methods=['POST'])
@jwt_required()
def add_group_member(group_id):
    user_id = int(get_jwt_identity())
    data = request.get_json()
    new_member_id = data.get('user_id')

    requester = GroupMember.query.filter_by(group_id=group_id, user_id=user_id).first()
    if not requester or requester.role != 'admin':
        return jsonify({"msg": "Only admins can add members"}), 403
    
    # Check if already member
    existing = GroupMember.query.filter_by(group_id=group_id, user_id=new_member_id).first()
    if existing:
        return jsonify({"msg": "User is already a member"}), 400

    # Verify friendship (Optional but good for privacy)
    # For now, let's assume admins can add anyone they know? 
    # Or strict: Admin must be friend with the user.
    # Let's check friendship.
    friendship = Friend.query.filter(
        ((Friend.user_id == user_id) & (Friend.friend_id == new_member_id)) |
        ((Friend.user_id == new_member_id) & (Friend.friend_id == user_id))
    ).first()
    
    if not friendship:
         return jsonify({"msg": "You can only add your friends"}), 400

    new_member = GroupMember(group_id=group_id, user_id=new_member_id, role='member')
    db.session.add(new_member)
    db.session.commit()
    
    return jsonify({"msg": "Member added"}), 200
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
        join_room(str(user_id)) # Join personal room for signaling
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
        'timestamp': msg.timestamp.isoformat() + 'Z',
        'conversation_id': msg.conversation_id,
        'group_id': msg.group_id,
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

@socketio.on('mark_seen')
def handle_mark_seen(data):
    user_id = get_user_id()
    if not user_id:
        return

    message_id = data.get('message_id')
    if not message_id:
        return

    # Check if already seen
    existing = MessageSeen.query.filter_by(message_id=message_id, user_id=user_id).first()
    if existing:
        return

    # Add seen record
    new_seen = MessageSeen(message_id=message_id, user_id=user_id)
    db.session.add(new_seen)
    
    # Broadcast update
    msg = db.session.get(Message, message_id)
    if msg:
        db.session.commit() # Commit to save ID
        
        # Get total seen count/users? For now count is enough for simple UI, or list of users
        # Let's send the user who just saw it
        user = db.session.get(User, user_id)
        
        payload = {
            "message_id": message_id,
            "user_id": user_id,
            "username": user.username,
            "seen_at": new_seen.seen_at.isoformat()
        }

        if msg.conversation_id:
            socketio.emit('message_seen_update', payload, room=f"private_{msg.conversation_id}")
        elif msg.group_id:
            socketio.emit('message_seen_update', payload, room=f"group_{msg.group_id}")


# === Whiteboard Events ===
@socketio.on('whiteboard_draw')
def handle_whiteboard_draw(data):
    user_id = get_user_id()
    if not user_id: 
        print("WB: No user ID")
        return

    chat_type = data.get('chat_type')
    try:
        chat_id = int(data.get('chat_id'))
    except:
        print("WB: Invalid ID")
        return
    
    room = None
    if chat_type == 'private':
        # Verify participation
        if Participant.query.filter_by(conversation_id=chat_id, user_id=user_id).first():
            room = f"private_{chat_id}"
    elif chat_type == 'group':
         if GroupMember.query.filter_by(group_id=chat_id, user_id=user_id).first():
            room = f"group_{chat_id}"

    print(f"WB Draw: User={user_id}, Type={chat_type}, ID={chat_id}, Room={room}")

    if room:
        # Broadcast to room (including sender? No, sender draws locally for zero latency)
        # But for simplicity, we can broadcast to everyone including sender (include_self=False)
        emit('whiteboard_draw', data, room=room, include_self=False)

@socketio.on('whiteboard_clear')
def handle_whiteboard_clear(data):
    user_id = get_user_id()
    chat_type = data.get('chat_type')
    try:
        chat_id = int(data.get('chat_id'))
    except:
        return
    
    room = None
    if chat_type == 'private':
        if Participant.query.filter_by(conversation_id=chat_id, user_id=user_id).first():
            room = f"private_{chat_id}"
    elif chat_type == 'group':
         if GroupMember.query.filter_by(group_id=chat_id, user_id=user_id).first():
            room = f"group_{chat_id}"

    if room:
        emit('whiteboard_clear', {}, room=room, include_self=False)

@socketio.on('whiteboard_update')
def handle_whiteboard_update(data):
    user_id = get_user_id()
    if not user_id: return
    
    # Broadcast update event (for moves/edits)
    # Similar structure to draw, just relaying
    chat_type = data.get('chat_type')
    try: chat_id = int(data.get('chat_id'))
    except: return
    
    room = _get_wb_room(user_id, chat_type, chat_id)
    if room:
        emit('whiteboard_update', data, room=room, include_self=False)

@socketio.on('whiteboard_delete')
def handle_whiteboard_delete(data):
    user_id = get_user_id()
    if not user_id: return
    
    chat_type = data.get('chat_type')
    try: chat_id = int(data.get('chat_id'))
    except: return
    
    room = _get_wb_room(user_id, chat_type, chat_id)
    if room:
        emit('whiteboard_delete', data, room=room, include_self=False)

@socketio.on('whiteboard_request_state')
def handle_wb_request_state(data):
    user_id = get_user_id()
    if not user_id: return
    
    chat_type = data.get('chat_type')
    try: chat_id = int(data.get('chat_id'))
    except: return
    
    room = _get_wb_room(user_id, chat_type, chat_id)
    if room:
        # Request state from OTHERS in the room
        # We ask ONE client to send the state? Or server maintains it?
        # Server doesn't have live state in RAM usually.
        # Option A: Relay "who has state?" -> Client responds -> Relay back.
        # Option B: Just let clients sync optimistically.
        # Better: Emit 'request_state_from_peers' to room (excluding sender).
        # The first peer to reply sends 'whiteboard_state_snapshot' which we forward to requester.
        emit('request_state_from_peers', {'requester_id': request.sid}, room=room, include_self=False)

@socketio.on('whiteboard_state_snapshot')
def handle_wb_snapshot(data):
    # Forward snapshot to specific requester
    requester_sid = data.get('requester_id')
    if requester_sid:
        emit('whiteboard_state_snapshot', data, room=requester_sid)

# Helper for room resolution (DRY)
def _get_wb_room(user_id, chat_type, chat_id):
    if chat_type == 'private':
        if Participant.query.filter_by(conversation_id=chat_id, user_id=user_id).first():
            return f"private_{chat_id}"
    elif chat_type == 'group':
         if GroupMember.query.filter_by(group_id=chat_id, user_id=user_id).first():
            return f"group_{chat_id}"
    return None



# === WebRTC Signaling Events ===

@socketio.on('call_user')
def on_call_user(data):
    user_to_call = data.get('user_to_call')
    sender_id = data.get('from')
    signal_data = data.get('signal_data')
    
    emit('incoming_call', {
        'signal': signal_data,
        'from': sender_id,
        'callType': 'audio' 
    }, room=str(user_to_call))


@socketio.on('answer_call')
def on_answer_call(data):
    caller_id = data.get('to')
    signal = data.get('signal')
    
    # Notify caller
    emit('call_accepted', {
        'signal': signal
    }, room=str(caller_id))
    
    # Notify my other devices to stop ringing
    sender_id = get_user_id()
    if sender_id:
        emit('call_answered_elsewhere', {}, room=str(sender_id), include_self=False)


@socketio.on('ice_candidate')
def on_ice_candidate(data):
    target_id = data.get('to')
    candidate = data.get('candidate')
    
    emit('ice_candidate', {
        'candidate': candidate,
        'from': get_user_id() 
    }, room=str(target_id))


@socketio.on('end_call')
def on_end_call(data):
    target_id = data.get('to')
    user_id = get_user_id()
    
    # Notify target
    emit('call_ended', {}, room=str(target_id))
    
    # Notify my other devices (and self, to be safe/consistent)
    if user_id:
        emit('call_ended', {}, room=str(user_id))



# === Whiteboard Standalone API ===

@app.route('/api/whiteboards', methods=['GET'])
@jwt_required()
def get_whiteboards():
    user_id = int(get_jwt_identity())
    boards = Whiteboard.query.filter_by(owner_id=user_id).order_by(Whiteboard.updated_at.desc()).all()
    return jsonify([{
        "id": b.id,
        "name": b.name,
        "updated_at": b.updated_at.isoformat() + 'Z',
        "thumbnail": b.thumbnail
    } for b in boards]), 200

@app.route('/api/whiteboards', methods=['POST'])
@jwt_required()
def create_whiteboard():
    user_id = int(get_jwt_identity())
    data = request.get_json()
    name = data.get('name', 'Untitled Whiteboard')
    
    board = Whiteboard(name=name, owner_id=user_id, data="[]") # Empty array init
    db.session.add(board)
    db.session.commit()
    
    return jsonify({
        "msg": "Whiteboard created",
        "id": board.id,
        "name": board.name
    }), 201

@app.route('/api/whiteboards/<int:board_id>', methods=['GET'])
@jwt_required()
def get_whiteboard_data(board_id):
    user_id = int(get_jwt_identity())
    board = db.session.get(Whiteboard, board_id)
    if not board:
        return jsonify({"msg": "Whiteboard not found"}), 404
    if board.owner_id != user_id:
        return jsonify({"msg": "Unauthorized"}), 403
    
    return jsonify({
        "id": board.id,
        "name": board.name,
        "data": board.data,
        "updated_at": board.updated_at.isoformat() + 'Z'
    }), 200

@app.route('/api/whiteboards/<int:board_id>/save', methods=['POST'])
@jwt_required()
def save_whiteboard(board_id):
    user_id = int(get_jwt_identity())
    board = db.session.get(Whiteboard, board_id)
    if not board:
        return jsonify({"msg": "Whiteboard not found"}), 404
    if board.owner_id != user_id:
        return jsonify({"msg": "Unauthorized"}), 403

    data = request.get_json()
    board.data = data.get('data') # JSON string expected
    board.name = data.get('name', board.name)
    if 'thumbnail' in data:
        board.thumbnail = data['thumbnail']
    
    board.updated_at = datetime.utcnow()
    db.session.commit()
    
    return jsonify({"msg": "Saved"}), 200

@app.route('/api/whiteboards/<int:board_id>', methods=['DELETE'])
@jwt_required()
def delete_whiteboard(board_id):
    user_id = int(get_jwt_identity())
    board = db.session.get(Whiteboard, board_id)
    if not board:
        return jsonify({"msg": "Whiteboard not found"}), 404
    if board.owner_id != user_id:
        return jsonify({"msg": "Unauthorized"}), 403
        
    db.session.delete(board)
    db.session.commit()
    return jsonify({"msg": "Deleted"}), 200


# === Run ===

@app.route('/api/notepads', methods=['GET'])
@jwt_required()
def get_notepads():
    user_id = int(get_jwt_identity())
    notes = Notepad.query.filter_by(user_id=user_id).order_by(Notepad.updated_at.desc()).all()
    return jsonify([{
        "id": n.id,
        "name": n.name,
        "content" : n.content,
        "updated_at": n.updated_at.isoformat()
    } for n in notes]), 200

@app.route('/api/notepads', methods=['POST'])
@jwt_required()
def create_notepad():
    user_id = int(get_jwt_identity())
    data = request.get_json()
    name = data.get('name', 'Untitled Note')
    
    note = Notepad(user_id=user_id, name=name, content="")
    db.session.add(note)
    db.session.commit()
    return jsonify({"id": note.id, "name": note.name}), 201

@app.route('/api/notepads/<int:id>', methods=['GET'])
@jwt_required()
def get_notepad(id):
    user_id = int(get_jwt_identity())
    note = Notepad.query.filter_by(id=id, user_id=user_id).first_or_404()
    return jsonify({
        "id": note.id,
        "name": note.name,
        "content": note.content,
        "updated_at": note.updated_at.isoformat()
    }), 200

@app.route('/api/notepads/<int:id>', methods=['POST'])
@jwt_required()
def update_notepad(id):
    user_id = int(get_jwt_identity())
    note = Notepad.query.filter_by(id=id, user_id=user_id).first_or_404()
    
    data = request.get_json()
    if 'name' in data:
        note.name = data['name']
    if 'content' in data:
        note.content = data['content']
    
    db.session.commit()
    return jsonify({"msg": "Saved"}), 200

@app.route('/api/notepads/<int:id>', methods=['DELETE'])
@jwt_required()
def delete_notepad(id):
    user_id = int(get_jwt_identity())
    note = Notepad.query.filter_by(id=id, user_id=user_id).first_or_404()
    db.session.delete(note)
    db.session.commit()
    return jsonify({"msg": "Deleted"}), 200

    return jsonify({"msg": "Deleted"}), 200

# === Status Routes ===

@app.route('/api/status/<int:status_id>', methods=['DELETE'])
@jwt_required()
def delete_status(status_id):
    user_id = int(get_jwt_identity())
    status = db.session.get(Status, status_id)
    if not status:
        return jsonify({'msg': 'Status not found'}), 404
    if status.user_id != user_id:
        return jsonify({'msg': 'Permission denied'}), 403
        
    db.session.delete(status)
    db.session.commit()
    return jsonify({'msg': 'Status deleted'}), 200

@app.route('/api/status/<int:status_id>/like', methods=['POST'])
@jwt_required()
def like_status(status_id):
    user_id = int(get_jwt_identity())
    status = db.session.get(Status, status_id)
    if not status:
        return jsonify({'msg': 'Status not found'}), 404
        
    existing_like = StatusLike.query.filter_by(status_id=status_id, user_id=user_id).first()
    if existing_like:
        db.session.delete(existing_like)
        liked = False
    else:
        new_like = StatusLike(status_id=status_id, user_id=user_id)
        db.session.add(new_like)
        liked = True
        
    db.session.commit()
    
    # Get current count
    count = StatusLike.query.filter_by(status_id=status_id).count()
    
    # Emit socket event for real-time update
    socketio.emit('status_like_update', {
        'status_id': status_id,
        'count': count,
        'liked': liked, # This is specific to the user triggering it, but clients can use count
        'user_id': user_id
    })
    
    return jsonify({'msg': 'Success', 'liked': liked, 'count': count}), 200

@app.route('/api/status', methods=['POST'])
@jwt_required()
def upload_status():
    user_id = int(get_jwt_identity())
    
    # Limit to 5 active statuses
    active_count = Status.query.filter_by(user_id=user_id).filter(Status.expires_at > datetime.utcnow()).count()
    if active_count >= 5:
        return jsonify({'msg': 'Maximum 5 active statuses allowed'}), 400

    # Handle Text Status
    if request.content_type.startswith('application/json'):
        data = request.get_json()
        content = data.get('content')
        if not content:
             return jsonify({'msg': 'No content'}), 400
        
        status = Status(
            user_id=user_id,
            type='text',
            content=content,
            expires_at=datetime.utcnow() + timedelta(hours=24)
        )
        db.session.add(status)
        db.session.commit()
        return jsonify({'msg': 'Status posted'}), 200
    
    # Handle File Status (Image/Video)
    if 'file' not in request.files:
         return jsonify({'msg': 'No file'}), 400
         
    file = request.files['file']
    filename = secure_filename(file.filename)
    ext = filename.split('.')[-1].lower()
    
    if ext in ['png', 'jpg', 'jpeg', 'webp', 'gif']:
        status_type = 'image'
    elif ext in ['mp4', 'webm', 'mov', 'avi', 'wmv', 'mkv', 'flv', 'hevc']:
        status_type = 'video'
        # Video Duration Check needs to be client-side usually for simple uploads, 
        # or we use ffprobe here. For now rely on frontend validation but we trust user slightly.
        # Or better: check size as rough proxy? No. 
        # We will strictly enforce in frontend, backend accepts.
    else:
        return jsonify({'msg': 'Invalid file type'}), 400
        
    try:
        url = upload_file_helper(file)
        status = Status(
            user_id=user_id, 
            type=status_type, 
            content=url,
            expires_at=datetime.utcnow() + timedelta(hours=24)
        )
        db.session.add(status)
        db.session.commit()
        return jsonify({'msg': 'Status posted'}), 200
    except Exception as e:
        print(f"Status upload error: {e}")
        return jsonify({'msg': 'Upload failed'}), 500

@app.route('/api/status', methods=['GET'])
@jwt_required()
def get_statuses():
    user_id = int(get_jwt_identity())
    
    # Helper to format status
    def format_status(s):
        likes_count = StatusLike.query.filter_by(status_id=s.id).count()
        is_liked = StatusLike.query.filter_by(status_id=s.id, user_id=user_id).first() is not None
        return {
            "id": s.id,
            "type": s.type,
            "content": s.content,
            "created_at": s.created_at.isoformat() + 'Z',
            "likes_count": likes_count,
            "is_liked": is_liked
        }

    # Get My Statuses
    my_statuses = Status.query.filter_by(user_id=user_id)\
        .filter(Status.expires_at > datetime.utcnow())\
        .order_by(Status.created_at.asc()).all()
        
    # Get Friends' Statuses
    # 1. Find friends
    friends = Friend.query.filter((Friend.user_id == user_id) | (Friend.friend_id == user_id)).all()
    friend_ids = [f.friend_id if f.user_id == user_id else f.user_id for f in friends]
    
    # 2. Query statuses
    
    raw_statuses = Status.query.filter(Status.user_id.in_(friend_ids))\
        .filter(Status.expires_at > datetime.utcnow())\
        .order_by(Status.created_at.asc()).all()
        
    # Group manually
    friends_status_map = {}
    for s in raw_statuses:
        if s.user_id not in friends_status_map:
            friends_status_map[s.user_id] = []
        friends_status_map[s.user_id].append(format_status(s))
        
    # Format for response
    # We need user details for each friend group
    result_friends = []
    for fid, statuses in friends_status_map.items():
        user = db.session.get(User, fid)
        if user:
            result_friends.append({
                "user_id": user.id,
                "username": user.username,
                "profile_image": user.profile_image,
                "statuses": statuses,
                "last_update": statuses[-1]['created_at']
            })
    
    # Sort friends by last update
    result_friends.sort(key=lambda x: x['last_update'], reverse=True)
    
    return jsonify({
        "my_status": [format_status(s) for s in my_statuses],
        "friends_status": result_friends
    }), 200


# === Share Routes (Clone) ===
@app.route('/api/whiteboards/<int:wb_id>/share', methods=['POST'])
@jwt_required()
def share_whiteboard(wb_id):
    user_id = int(get_jwt_identity())
    data = request.get_json()
    target_user_id = data.get('target_user_id')
    
    original = db.session.get(Whiteboard, wb_id)
    if not original or original.owner_id != user_id:
         return jsonify({'msg': 'Whiteboard not found or permission denied'}), 403
         
    # Clone
    new_wb = Whiteboard(
        name=f"{original.name} (Shared)",
        owner_id=target_user_id,
        data=original.data,
        thumbnail=original.thumbnail
    )
    db.session.add(new_wb)
    db.session.commit()
    return jsonify({'msg': 'Shared successfully'}), 200

@app.route('/api/notepads/<int:note_id>/share', methods=['POST'])
@jwt_required()
def share_notepad(note_id):
    user_id = int(get_jwt_identity())
    data = request.get_json()
    target_user_id = data.get('target_user_id')
    
    original = db.session.get(Notepad, note_id)
    if not original or original.user_id != user_id:
         return jsonify({'msg': 'Notepad not found or permission denied'}), 403
         
    # Clone
    new_note = Notepad(
        name=f"{original.name} (Shared)",
        user_id=target_user_id,
        content=original.content
    )
    db.session.add(new_note)
    db.session.commit()
    return jsonify({'msg': 'Shared successfully'}), 200

# === DELTA AI Route ===
@app.route('/api/delta/ask', methods=['POST'])
@jwt_required()
def ask_delta():
    try:
        data = request.get_json()
        note_content = data.get('content', '')
        action = data.get('action', 'summarize') # summarize, action_items, polish, expand, qa, explain_code
        user_query = data.get('query', '') # For Q&A

        if not note_content:
            return jsonify({"msg": "Note content is empty"}), 400

        # Construct Prompt
        prompt = ""
        if action == 'summarize':
            prompt = f"Summarize the following note concisely:\\n\\n{note_content}"
        elif action == 'action_items':
            prompt = f"Extract a checklist of action items/tasks from this note. Return them as a markdown list:\\n\\n{note_content}"
        elif action == 'polish':
            prompt = f"Rewrite the following text to be more professional, fix grammar, and improve clarity:\\n\\n{note_content}"
        elif action == 'expand':
            prompt = f"Expand on the following points, adding relevant details and creative ideas:\\n\\n{note_content}"
        elif action == 'qa':
            if not user_query:
                return jsonify({"msg": "Query required for Q&A"}), 400
            prompt = f"Based ONLY on the following note, answer the question: '{user_query}'\\n\\nNote Content:\\n{note_content}"
        elif action == 'explain_code':
            prompt = f"Explain the following code snippet simply:\\n\\n{note_content}"
        else:
            return jsonify({"msg": "Invalid action"}), 400

        # Call Gemini with Fallbacks
        model_names = ['gemini-1.5-flash', 'gemini-1.5-flash-001', 'gemini-pro', 'gemini-1.0-pro-latest']
        last_error = None
        
        for m_name in model_names:
            try:
                # print(f"Trying model: {m_name}")
                model = genai.GenerativeModel(m_name)
                response = model.generate_content(prompt)
                return jsonify({"result": response.text}), 200
            except Exception as e:
                last_error = e
                # Continue to next model
        
        # If all failed, gather debug info
        available_models = []
        try:
            for m in genai.list_models():
                if 'generateContent' in m.supported_generation_methods:
                    available_models.append(m.name)
        except Exception as e2:
            available_models = [f"Could not list models: {str(e2)}"]

        error_msg = f"All models failed. Last error: {str(last_error)}. AVAILABLE MODELS: {', '.join(available_models)}"
        print(error_msg)
        return jsonify({"msg": error_msg}), 500

    except Exception as e:

    except Exception as e:
        print(f"DELTA AI Error: {e}")
        return jsonify({"msg": str(e)}), 500

if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
