import os
from flask import Flask, request, jsonify, send_from_directory, url_for
from flask_jwt_extended import JWTManager, jwt_required, get_jwt_identity, create_access_token
from flask_mail import Mail, Message as MailMessage
from flask_socketio import SocketIO, join_room, leave_room, emit
from werkzeug.utils import secure_filename
from PIL import Image
from datetime import datetime
import uuid
from flask_cors import CORS
from config import Config
from models import db, User, EmailOTP, FriendRequest, Friend, Conversation, Participant, Message, Reaction, Group, \
    GroupMember
from supabase import create_client
SUPABASE_URL = "https://qsvowzmqrxelfrkzvqnp.supabase.co"
SUPABASE_KEY = "sb_publishable_LeWjFfX9IA44laDvDykgcA_LCCi-Fln"

supabase = create_client(SUPABASE_URL, SUPABASE_KEY)


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    CORS(app, origins=["http://localhost:63342", "http://127.0.0.1:5000", "null"])

    db.init_app(app)
    jwt = JWTManager(app)
    mail = Mail(app)
    socketio = SocketIO(app, cors_allowed_origins="*", async_mode="eventlet")

    # -------------------------
    # Helper Functions
    # -------------------------

    def get_conversation_id(user1_id, user2_id):
        conv = db.session.query(Conversation).join(Participant).filter(
            Participant.user_id.in_([user1_id, user2_id])
        ).group_by(Conversation.id).having(db.func.count(Participant.id) == 2).first()
        return conv.id if conv else None

    def create_private_conversation(user1_id, user2_id):
        conv = Conversation()
        db.session.add(conv)
        db.session.flush()
        p1 = Participant(conversation_id=conv.id, user_id=user1_id)
        p2 = Participant(conversation_id=conv.id, user_id=user2_id)
        db.session.add_all([p1, p2])
        db.session.commit()
        return conv.id

    def is_participant(conversation_id, user_id):
        return db.session.query(Participant).filter_by(
            conversation_id=conversation_id, user_id=user_id
        ).first() is not None

    def is_group_member(group_id, user_id):
        return db.session.query(GroupMember).filter_by(
            group_id=group_id, user_id=user_id
        ).first() is not None

    def send_otp_email(email, otp):
        msg = MailMessage(
            subject="Your ABARG OTP Code",
            recipients=[email],
            body=f"Your OTP code is: {otp}. It expires in 10 minutes."
        )
        try:
            mail.send(msg)
        except Exception as e:
            print(f"Failed to send email: {e}")

    # -------------------------
    # REST APIs
    # -------------------------

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

        existing_by_username = User.query.filter_by(username=username).first()
        if existing_by_username and existing_by_username.is_verified:
            return jsonify({"msg": "Username taken"}), 400

        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        otp = EmailOTP.create_otp(email)
        send_otp_email(email, otp)

        return jsonify({"msg": "User created. Check email for OTP."}), 201

    @app.route('/verify-otp', methods=['POST'])
    def verify_otp():
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

    @app.route('/login', methods=['POST'])
    def login():
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        user = User.query.filter_by(email=email).first()
        if not user:
            user = User.query.filter_by(username=email).first()
        if not user or not user.check_password(password):
            return jsonify({"msg": "Bad email or username or password"}), 401
        if not user.is_verified:
            return jsonify({"msg": "Email not verified"}), 403
        access_token = create_access_token(identity=str(user.id))
        return jsonify(access_token=access_token), 200

    @app.route('/profile', methods=['GET'])
    @jwt_required()
    def profile():
        user_id = get_jwt_identity()
        user = User.query.get(int(user_id))
        return jsonify({
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "profile_image": user.profile_image
        })

    @app.route('/friends', methods=['GET'])
    @jwt_required()
    def get_friends():
        user_id = get_jwt_identity()
        friends = db.session.query(User).join(Friend, Friend.friend_id == User.id).filter(
            Friend.user_id == int(user_id)).all()
        return jsonify([{
            "id": f.id,
            "username": f.username,
            "profile_image": f.profile_image
        } for f in friends])

    @app.route('/conversation-with/<int:friend_id>', methods=['GET'])
    @jwt_required()
    def get_conversation_with(friend_id):
        user_id = int(get_jwt_identity())

        # Try to find existing conversation using Participant table
        conv = db.session.query(Conversation).join(Participant).filter(
            Participant.user_id.in_([user_id, friend_id])
        ).group_by(Conversation.id).having(db.func.count(Participant.id) == 2).first()

        # If not found, create one
        if not conv:
            conv = Conversation()
            db.session.add(conv)
            db.session.flush()

            p1 = Participant(conversation_id=conv.id, user_id=user_id)
            p2 = Participant(conversation_id=conv.id, user_id=friend_id)

            db.session.add_all([p1, p2])
            db.session.commit()

        return jsonify({
            "conversation_id": conv.id
        })

    @app.route('/friend-requests/send', methods=['POST'])
    @jwt_required()
    def send_friend_request():
        user_id = get_jwt_identity()
        data = request.get_json()
        username = data.get('username')
        target = User.query.filter_by(username=username).first()
        if not target:
            return jsonify({"msg": "User not found"}), 404
        if target.id == int(user_id):
            return jsonify({"msg": "Cannot add yourself"}), 400
        existing = FriendRequest.query.filter(
            ((FriendRequest.from_user_id == int(user_id)) & (FriendRequest.to_user_id == target.id)) |
            ((FriendRequest.from_user_id == target.id) & (FriendRequest.to_user_id == int(user_id)))
        ).first()
        if existing:
            return jsonify({"msg": "Request already exists"}), 400
        req = FriendRequest(from_user_id=int(user_id), to_user_id=target.id)
        db.session.add(req)
        db.session.commit()
        return jsonify({"msg": "Friend request sent"}), 201

    @app.route('/friend-requests/incoming', methods=['GET'])
    @jwt_required()
    def incoming_requests():
        user_id = get_jwt_identity()
        requests = FriendRequest.query.filter_by(to_user_id=int(user_id), status='pending').all()
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
        user_id = get_jwt_identity()
        req = FriendRequest.query.filter_by(id=request_id, to_user_id=int(user_id), status='pending').first_or_404()
        req.status = 'accepted'
        f1 = Friend(user_id=req.to_user_id, friend_id=req.from_user_id)
        f2 = Friend(user_id=req.from_user_id, friend_id=req.to_user_id)
        db.session.add_all([f1, f2])
        create_private_conversation(req.from_user_id, req.to_user_id)
        db.session.commit()
        return jsonify({"msg": "Friend added"}), 200

    @app.route('/friend-requests/<int:request_id>/reject', methods=['POST'])
    @jwt_required()
    def reject_friend_request(request_id):
        user_id = get_jwt_identity()
        req = FriendRequest.query.filter_by(id=request_id, to_user_id=int(user_id), status='pending').first_or_404()
        req.status = 'rejected'
        db.session.commit()
        return jsonify({"msg": "Request rejected"}), 200

    @app.route('/chat/history/<int:conversation_id>', methods=['GET'])
    @jwt_required()
    def chat_history(conversation_id):
        user_id = get_jwt_identity()
        if not is_participant(conversation_id, int(user_id)):
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

        if not is_participant(conversation_id, user_id):
            return jsonify({"msg": "Unauthorized"}), 403

        # Delete reactions
        msgs = Message.query.filter_by(conversation_id=conversation_id).all()
        for m in msgs:
            Reaction.query.filter_by(message_id=m.id).delete()

        # Delete messages
        Message.query.filter_by(conversation_id=conversation_id).delete()

        # Delete participants
        Participant.query.filter_by(conversation_id=conversation_id).delete()

        # Delete conversation
        Conversation.query.filter_by(id=conversation_id).delete()

        db.session.commit()
        return jsonify({"msg": "Chat deleted"}), 200

    @app.route('/group-chat/history/<int:group_id>', methods=['GET'])
    @jwt_required()
    def group_chat_history(group_id):
        user_id = get_jwt_identity()
        if not is_group_member(group_id, int(user_id)):
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

        # Only creator can delete
        if group.created_by != user_id:
            return jsonify({"msg": "Only group creator can delete this group"}), 403

        # Delete reactions
        msgs = Message.query.filter_by(group_id=group_id).all()
        for m in msgs:
            Reaction.query.filter_by(message_id=m.id).delete()

        # Delete messages
        Message.query.filter_by(group_id=group_id).delete()

        # Delete members
        GroupMember.query.filter_by(group_id=group_id).delete()

        # Delete group
        Group.query.filter_by(id=group_id).delete()

        db.session.commit()
        return jsonify({"msg": "Group deleted"}), 200

    @app.route('/upload-image', methods=['POST'])
    @jwt_required()
    def upload_image():
        if 'image' not in request.files:
            return jsonify({"msg": "No image"}), 400

        file = request.files['image']
        ext = secure_filename(file.filename).split('.')[-1].lower()

        if ext not in ['png', 'jpg', 'jpeg', 'gif', 'webp']:
            return jsonify({"msg": "Invalid image type"}), 400

        filename = f"{uuid.uuid4().hex}.{ext}"

        # Upload to Supabase
        supabase.storage.from_("uploads").upload(filename, file.read())

        url = f"{SUPABASE_URL}/storage/v1/object/public/uploads/{filename}"

        return jsonify({"url": url}), 201



    # -------------------------
    # GROUP CHAT APIs
    # -------------------------

    @app.route('/groups/create', methods=['POST'])
    @jwt_required()
    def create_group():
        user_id = get_jwt_identity()
        data = request.get_json()
        group_name = data.get('group_name')
        member_ids = data.get('member_ids', [])

        if not group_name:
            return jsonify({"msg": "Group name required"}), 400

        # Create group
        group = Group(name=group_name, created_by=int(user_id))
        db.session.add(group)
        db.session.flush()

        # Add creator as member
        creator_member = GroupMember(group_id=group.id, user_id=int(user_id))
        db.session.add(creator_member)

        # Add other members
        for member_id in member_ids:
            if member_id != int(user_id):  # Don't add creator twice
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
        user_id = get_jwt_identity()
        groups = db.session.query(Group).join(GroupMember).filter(
            GroupMember.user_id == int(user_id)
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
        user_id = get_jwt_identity()
        if not is_group_member(group_id, int(user_id)):
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

    @app.route('/groups/<int:group_id>/add-member', methods=['POST'])
    @jwt_required()
    def add_group_member(group_id):
        user_id = get_jwt_identity()
        if not is_group_member(group_id, int(user_id)):
            return jsonify({"msg": "Unauthorized"}), 403

        data = request.get_json()
        new_member_id = data.get('user_id')

        if not new_member_id:
            return jsonify({"msg": "User ID required"}), 400

        # Check if user already in group
        existing = GroupMember.query.filter_by(
            group_id=group_id, user_id=new_member_id
        ).first()
        if existing:
            return jsonify({"msg": "User already in group"}), 400

        # Add member
        new_member = GroupMember(group_id=group_id, user_id=new_member_id)
        db.session.add(new_member)
        db.session.commit()

        # Notify group members via socket (optional)
        room = f'group_{group_id}'
        emit('group_member_added', {
            "group_id": group_id,
            "user_id": new_member_id,
            "username": User.query.get(new_member_id).username
        }, room=room)

        return jsonify({"msg": "Member added successfully"}), 200

    # -------------------------
    # Socket.IO Events
    # -------------------------

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
            print(f"✅ User {user_id} connected with SID {request.sid}")
            return True
        except Exception as e:
            print(f"❌ Socket auth failed: {e}")
            return False

    @socketio.on('disconnect')
    def handle_disconnect():
        user_id = user_sessions.pop(request.sid, None)
        if user_id:
            print(f"✅ User {user_id} disconnected")

    def get_user_id():
        return user_sessions.get(request.sid)

    @socketio.on('join_private_chat')
    def handle_join_private(data):
        user_id = get_user_id()
        if not user_id:
            emit('error', {'msg': 'Authentication required'})
            return

        conversation_id = data['conversation_id']
        if not is_participant(conversation_id, user_id):
            emit('error', {'msg': 'Not authorized for this conversation'})
            return

        room = f'private_{conversation_id}'
        join_room(room)
        print(f"✅ User {user_id} joined room {room}")
        emit('joined', {'room': room})

    @socketio.on('join_group_chat')
    def handle_join_group(data):
        user_id = get_user_id()
        if not user_id:
            emit('error', {'msg': 'Authentication required'})
            return

        group_id = data['group_id']
        if not is_group_member(group_id, user_id):
            emit('error', {'msg': 'Not authorized for this group'})
            return

        room = f'group_{group_id}'
        join_room(room)
        print(f"✅ User {user_id} joined group room {room}")
        emit('joined_group', {'room': room})

    @app.route('/profile/upload-dp', methods=['POST'])
    @jwt_required()
    def upload_profile_dp():
        user_id = int(get_jwt_identity())

        if 'image' not in request.files:
            return jsonify({"msg": "No image"}), 400

        file = request.files['image']
        ext = secure_filename(file.filename).split('.')[-1].lower()

        if ext not in ['png', 'jpg', 'jpeg', 'webp']:
            return jsonify({"msg": "Invalid image type"}), 400

        filename = f"profile_{user_id}_{uuid.uuid4().hex}.{ext}"

        supabase.storage.from_("uploads").upload(filename, file.read())

        url = f"{SUPABASE_URL}/storage/v1/object/public/uploads/{filename}"

        user = User.query.get(user_id)
        user.profile_image = url
        db.session.commit()

        return jsonify({"url": url}), 200

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

        if conversation_id:
            if not is_participant(conversation_id, user_id):
                emit('error', {'msg': 'Not authorized'})
                return

            msg = Message(
                conversation_id=conversation_id,
                sender_id=user_id,
                content=content,
                image_url=image_url
            )
            db.session.add(msg)
            db.session.commit()

            room = f'private_{conversation_id}'
            emit('new_message', {
                'id': msg.id,
                'sender_id': msg.sender_id,
                'sender_name': User.query.get(user_id).username,
                'content': msg.content,
                'image_url': msg.image_url,
                'timestamp': msg.timestamp.isoformat(),
                'reactions': {}
            }, room=room)

        elif group_id:
            if not is_group_member(group_id, user_id):
                emit('error', {'msg': 'Not authorized'})
                return

            msg = Message(
                group_id=group_id,
                sender_id=user_id,
                content=content,
                image_url=image_url
            )
            db.session.add(msg)
            db.session.commit()

            room = f'group_{group_id}'
            emit('new_group_message', {
                'id': msg.id,
                'sender_id': msg.sender_id,
                'sender_name': User.query.get(user_id).username,
                'content': msg.content,
                'image_url': msg.image_url,
                'timestamp': msg.timestamp.isoformat(),
                'reactions': {}
            }, room=room)

        else:
            emit('error', {'msg': 'Invalid chat type'})

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

        # Check authorization for private chat
        if msg.conversation_id and not is_participant(msg.conversation_id, user_id):
            emit('error', {'msg': 'Not authorized'})
            return

        # Check authorization for group chat
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

        # Broadcast to appropriate room
        if msg.conversation_id:
            room = f'private_{msg.conversation_id}'
            emit('reaction_update', {
                'message_id': message_id,
                'reactions': reaction_counts
            }, room=room)
        elif msg.group_id:
            room = f'group_{msg.group_id}'
            emit('reaction_update', {
                'message_id': message_id,
                'reactions': reaction_counts
            }, room=room)

    return app, socketio

    if __name__ == '__main__':
        socketio.run(app, host='0.0.0.0', port=5000)
