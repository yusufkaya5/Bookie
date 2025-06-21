from flask import Flask, render_template, redirect, url_for, request, flash, session, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os, random, string
from datetime import datetime
from werkzeug.utils import secure_filename
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
from functools import wraps
from flask import abort

app = Flask(__name__)
app.config['SECRET_KEY'] = 'thisisasecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///bookie.db'
app.config['UPLOAD_FOLDER'] = 'uploads/'

if not os.path.exists('uploads'):
    os.mkdir('uploads')

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'bookieapp25@gmail.com'
app.config['MAIL_PASSWORD'] = 'fyau xxxo gmfc hwhn' 
app.config['MAIL_DEFAULT_SENDER'] = 'bookieapp25@gmail.com'

mail = Mail(app)
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    is_verified = db.Column(db.Boolean, default=False)
    is_admin = db.Column(db.Boolean, default=False)

    clubs = db.relationship('Club', backref='creator', lazy=True)
    comments = db.relationship('Comment', backref='author', lazy=True)
    join_requests = db.relationship('JoinRequest', backref='user', lazy=True)
    theme = db.Column(db.String(20), default='light')
    notifications = db.relationship('Notification', backref='recipient', lazy=True)

class Club(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    code = db.Column(db.String(6), unique=True, nullable=False)
    image = db.Column(db.String(200))
    is_private = db.Column(db.Boolean, default=False)  
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    books = db.relationship('Book', backref='club', lazy=True, cascade="all, delete-orphan")
    members = db.relationship('ClubMember', backref='club', lazy=True, cascade="all, delete-orphan")
    join_requests = db.relationship('JoinRequest', backref='club', lazy=True, cascade="all, delete-orphan")
    description = db.Column(db.Text)
    rules = db.Column(db.Text)

class ClubMember(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    club_id = db.Column(db.Integer, db.ForeignKey('club.id'), nullable=False)
    role = db.Column(db.String(50), default='member')  

    user = db.relationship('User', backref='memberships')

class Book(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    image = db.Column(db.String(200))
    club_id = db.Column(db.Integer, db.ForeignKey('club.id'), nullable=False)

    comments = db.relationship('Comment', backref='book', lazy=True, cascade="all, delete-orphan")

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    book_id = db.Column(db.Integer, db.ForeignKey('book.id'), nullable=False)

class JoinRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    club_id = db.Column(db.Integer, db.ForeignKey('club.id'), nullable=False)
    status = db.Column(db.String(20), default='pending')  

class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    message = db.Column(db.String(300), nullable=False)
    is_read = db.Column(db.Boolean, default=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def generate_code():
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/')
def home():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/toggle_theme')
@login_required
def toggle_theme():
    current_user.theme = 'dark' if current_user.theme == 'light' else 'light'
    db.session.commit()
    flash('Theme updated.')
    return redirect(request.referrer or url_for('dashboard'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        if User.query.filter((User.username == username) | (User.email == email)).first():
            flash('Username or email already exists.')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)
        new_user = User(username=username, email=email, password=hashed_password, is_verified=False)
        db.session.add(new_user)
        db.session.commit()

        token = serializer.dumps(email, salt='email-confirm-salt')
        confirm_url = url_for('confirm_email', token=token, _external=True)
        
        logo_url = "https://i.imgur.com/JQBaIYc.png"

        html = render_template('activate.html', confirm_url=confirm_url, logo_url=logo_url)
        msg = Message("Please confirm your email", recipients=[email], html=html)

        try:
            mail.send(msg)
            flash('Confirmation email sent!', 'info')
        except Exception as e:
            flash(f"Error sending email: {e}", 'danger')

        return redirect(url_for('login'))
    return render_template('register.html')


def generate_verification_token(email):
    return serializer.dumps(email, salt='email-confirm-salt')

def confirm_verification_token(token, expiration=3600):
    try:
        email = serializer.loads(token, salt='email-confirm-salt', max_age=expiration)
    except:
        return False
    return email

@app.route('/resend_confirmation', methods=['GET', 'POST'])
def resend_confirmation():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        if user:
            if user.is_verified:
                flash('This account is already verified.', 'info')
                return redirect(url_for('login'))

            token = serializer.dumps(user.email, salt='email-confirm-salt')
            confirm_url = url_for('confirm_email', token=token, _external=True)
            logo_url = "https://i.imgur.com/JQBaIYc.png"  

            html = render_template('activate.html', confirm_url=confirm_url, logo_url=logo_url)
            subject = "Confirm your Bookie account"

            msg = Message(subject, recipients=[user.email], html=html)
            try:
                mail.send(msg)
                flash('A new confirmation email has been sent.', 'info')
            except Exception as e:
                flash('Error sending email: ' + str(e), 'danger')
        else:
            flash('Email not found.', 'danger')

        return redirect(url_for('login'))

    return render_template('resend_confirmation.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            if not user.is_verified:
                flash('Please verify your email address before logging in.', 'warning')
                return redirect(url_for('login'))

            login_user(user)
            return redirect(url_for('dashboard'))

        flash('Login failed. Check your credentials.')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    created_clubs = Club.query.filter_by(creator_id=current_user.id).all()
    joined_club_ids = [m.club_id for m in ClubMember.query.filter_by(user_id=current_user.id).all()]
    joined_clubs = Club.query.filter(Club.id.in_(joined_club_ids)).filter(Club.creator_id != current_user.id).all()

   # created_clubs = Club.query.filter_by(creator_id=current_user.id).all()
   # joined_club_ids = [m.club_id for m in ClubMember.query.filter_by(user_id=current_user.id).all()]
   # joined_clubs = Club.query.filter(Club.id.in_(joined_club_ids)).all()
    return render_template('dashboard.html', created_clubs=created_clubs, joined_clubs=joined_clubs)

def create_notification(user_id, message, send_email=False):
    notif = Notification(user_id=user_id, message=message)
    db.session.add(notif)
    db.session.commit()

    if send_email:
        user = User.query.get(user_id)
        logo_url = url_for('static', filename='logo.png', _external=True)
        msg = Message("New Notification", recipients=[user.email],
                      html=render_template('notification.html', message=message, logo_url=logo_url))
        try:
            mail.send(msg)
        except Exception as e:
            print("Mail failed:", e)

@app.route('/notifications')
@login_required
def view_notifications():
    notifs = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.timestamp.desc()).all()
    return render_template('notifications.html', notifications=notifs)

@app.route('/club/<int:club_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_club(club_id):
    club = Club.query.get_or_404(club_id)

    if not (current_user.is_admin or current_user.id == club.creator_id):
        abort(403)

    if request.method == 'POST':
        club.description = request.form.get('description')
        club.rules = request.form.get('rules')
        db.session.commit()
        flash("Club updated.")
        return redirect(url_for('club_detail', club_id=club.id))

    return render_template('edit_club.html', club=club)

@app.route('/create_club', methods=['GET', 'POST'])
@login_required
def create_club():
    if request.method == 'POST':
        name = request.form['name']
        description = request.form.get('description')
        rules = request.form.get('rules')

        image = request.files['image']
        filename = None
        if image and allowed_file(image.filename):
            filename = secure_filename(image.filename)
            image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

        new_club = Club(
            name=name,
            code=generate_code(),
            image=filename,
            creator_id=current_user.id,
            description=description,
            rules=rules,
            is_private = 'is_private' in request.form 
        )
        db.session.add(new_club)
        db.session.commit()

        if not ClubMember.query.filter_by(user_id=current_user.id, club_id=new_club.id).first():
            member = ClubMember(user_id=current_user.id, club_id=new_club.id, role='president')
            db.session.add(member)
            db.session.commit()

        return redirect(url_for('dashboard'))
    return render_template('create_club.html')

@app.route('/join_club', methods=['GET', 'POST'])
@login_required
def join_club():
    if request.method == 'POST':
        code = request.form['code']
        club = Club.query.filter_by(code=code).first()

        if not club:
            flash('Invalid club code.')
            return redirect(url_for('join_club'))

        existing_member = ClubMember.query.filter_by(user_id=current_user.id, club_id=club.id).first()
        if existing_member:
            flash('You are already a member of this club.')
            return redirect(url_for('dashboard'))

        if club.is_private:
            # İstek zaten gönderilmiş mi?
            if not JoinRequest.query.filter_by(user_id=current_user.id, club_id=club.id).first():
                db.session.add(JoinRequest(user_id=current_user.id, club_id=club.id))
                db.session.commit()
                flash('Request sent. Please wait for approval.')
            else:
                flash('You have already requested to join this club.')
        else:
            member = ClubMember(user_id=current_user.id, club_id=club.id)
            db.session.add(member)
            db.session.commit()
            flash('Successfully joined the club.')
        return redirect(url_for('dashboard'))

    return render_template('join_club.html')

@app.route('/leave_club/<int:club_id>', methods=['POST'])
@login_required
def leave_club(club_id):
    membership = ClubMember.query.filter_by(user_id=current_user.id, club_id=club_id).first()
    if membership:
        db.session.delete(membership)
        db.session.commit()
        flash('You have left the club.', 'warning')
    else:
        flash('You are not a member of this club.', 'danger')
    return redirect(url_for('dashboard'))


@app.route('/club/<int:club_id>')
@login_required
def club_detail(club_id):
    club = Club.query.get_or_404(club_id)
    is_admin = current_user.is_admin
    is_creator = current_user.id == club.creator_id

    membership = ClubMember.query.filter_by(club_id=club_id, user_id=current_user.id).first()
    join_request = JoinRequest.query.filter_by(club_id=club_id, user_id=current_user.id).first()

    if not membership and not current_user.is_admin:
        if club.is_private:
            if join_request and join_request.status == 'pending':
                flash("Your join request is pending approval.", "warning")
            elif join_request and join_request.status == 'rejected':
                flash("Your join request was rejected.", "danger")
            else:
                flash("You are not authorized to view this private club.", "danger")
            return redirect(url_for('dashboard'))

    is_president = is_creator
    is_moderator = membership and membership.role == 'moderator'
    can_manage = is_admin or is_president or is_moderator

    books = club.books
    members = ClubMember.query.filter_by(club_id=club.id).all()
    #BURAYI EKLEDİM EN SON:
    requests = JoinRequest.query.filter_by(club_id=club_id, status='pending').all()
    pending_requests = len(requests)

    
    return render_template('club_detail.html', club=club, books=books, members=members,
                           is_admin=is_admin, is_president=is_president,
                           is_moderator=is_moderator, can_manage=can_manage, pending_requests=pending_requests) 


@app.route('/club/<int:club_id>/toggle_privacy', methods=['POST'])
@login_required
def toggle_privacy(club_id):
    club = Club.query.get_or_404(club_id)
    if current_user.is_admin or current_user.id == club.creator_id or has_role(club_id, ['president']):
        club.is_private = not club.is_private
        db.session.commit()
        flash('Club privacy updated.', 'info')
    else:
        abort(403)
    return redirect(url_for('club_detail', club_id=club_id))

@app.route('/club/<int:club_id>/remove/<int:user_id>')
@login_required
def remove_from_club(club_id, user_id):
    club = Club.query.get_or_404(club_id)
    member = ClubMember.query.filter_by(club_id=club_id, user_id=user_id).first_or_404()

    if current_user.is_admin or current_user.id == club.creator_id:
        db.session.delete(member)
        db.session.commit()
        flash("User removed from club.", "info")
    else:
        abort(403)

    return redirect(url_for('manage_roles', club_id=club_id))

@app.route('/club/<int:club_id>/requests')
@login_required
def view_requests(club_id):
    club = Club.query.get_or_404(club_id)
    if not has_role(club_id, roles=['president', 'moderator']):
        flash('Only moderators or presidents can view join requests.')
        return redirect(url_for('dashboard'))

    requests = JoinRequest.query.filter_by(club_id=club_id, status='pending').all()
    return render_template('join_requests.html', club=club, requests=requests)

@app.route('/approve_request/<int:request_id>')
@login_required
def approve_request(request_id):
    req = JoinRequest.query.get_or_404(request_id)
    club_id = req.club_id
    if not has_role(club_id, ['president', 'moderator']):
        abort(403)

    req.status = 'approved'
    db.session.add(ClubMember(user_id=req.user_id, club_id=club_id))
    db.session.commit()
    flash('Request approved.')
    create_notification(req.user_id, f"Your join request to '{req.club.name}' has been approved.", send_email=True)
    return redirect(url_for('view_requests', club_id=club_id))

@app.route('/club/<int:club_id>/manage_roles', methods=['GET', 'POST'])
@login_required
def manage_roles(club_id):
    club = Club.query.get_or_404(club_id)

    if not (current_user.is_admin or current_user.id == club.creator_id or has_role(club_id, roles=['president'])):
        abort(403)

    members = ClubMember.query.filter_by(club_id=club_id).all()

    if request.method == 'POST':
        for member in members:
            role = request.form.get(f'role_{member.user_id}')
            if role in ['member', 'moderator', 'president']:
                if role == 'president' and not (current_user.is_admin or current_user.id == club.creator_id):
                    continue
                member.role = role
        db.session.commit()
        flash("Roles updated.")
        return redirect(url_for('manage_roles', club_id=club_id))

    return render_template('manage_roles.html', club=club, members=members)

@app.route('/reject_request/<int:request_id>')
@login_required
def reject_request(request_id):
    req = JoinRequest.query.get_or_404(request_id)
    club_id = req.club_id
    if not has_role(club_id, ['president', 'moderator']):
        abort(403)

    req.status = 'rejected'
    db.session.commit()
    flash('Request rejected.')
    create_notification(req.user_id, f"Your join request to '{req.club.name}' has been rejected.", send_email=True)
    return redirect(url_for('view_requests', club_id=club_id))

@app.route('/add_book/<int:club_id>', methods=['POST'])
@login_required
def add_book(club_id):
    club = Club.query.get_or_404(club_id)

    if not has_role(club_id, roles=['president', 'moderator']):
        flash('Only moderators or presidents can add books.')
        return redirect(url_for('club_detail', club_id=club_id))

    title = request.form['title']
    image = request.files['image']
    filename = None
    if image and allowed_file(image.filename):
        filename = secure_filename(image.filename)
        image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

    new_book = Book(title=title, image=filename, club_id=club.id)
    db.session.add(new_book)
    db.session.commit()

    members = ClubMember.query.filter_by(club_id=club.id).all()
    for member in members:
        if member.user_id != current_user.id: 
            create_notification(
                user_id=member.user_id,
                message=f"📚 A new book titled <strong>{title}</strong> was added to <strong>{club.name}</strong>.",
                send_email=True
            )

    flash('Book added and notifications sent.')
    return redirect(url_for('club_detail', club_id=club_id))

def has_role(club_id, roles=['president']):
    if current_user.is_admin:
        return True
    member = ClubMember.query.filter_by(club_id=club_id, user_id=current_user.id).first()
    return member and member.role in roles

@app.route('/delete_club/<int:club_id>', methods=['POST'])
@login_required
def delete_club(club_id):
    club = Club.query.get_or_404(club_id)
    if current_user.id == club.creator_id or current_user.is_admin:
        db.session.delete(club)
        db.session.commit()
        flash("Club deleted.", "info")
    else:
        abort(403)
    return redirect(url_for('dashboard'))

@app.route('/delete_book/<int:book_id>/<int:club_id>')
@login_required
def delete_book(book_id, club_id):
    book = Book.query.get_or_404(book_id)
    club = Club.query.get_or_404(club_id)
    if current_user.id == club.creator_id:
        db.session.delete(book)
        db.session.commit()
    return redirect(url_for('club_detail', club_id=club_id))

@app.route('/comment/<int:book_id>', methods=['POST'])
@login_required
def comment(book_id):
    content = request.form['content']
    new_comment = Comment(content=content, user_id=current_user.id, book_id=book_id)
    db.session.add(new_comment)
    db.session.commit()

    club = new_comment.book.club
    club_members = ClubMember.query.filter_by(club_id=club.id).all()

    for member in club_members:
        if member.user_id != current_user.id:
            create_notification(
                user_id=member.user_id,
                message=f"💬 <strong>{current_user.username}</strong> commented on <strong>{new_comment.book.title}</strong> in <strong>{club.name}</strong>.",
                send_email=True
            )

    flash("Comment posted and notifications sent.")
    return redirect(request.referrer or url_for('dashboard'))

@app.route('/delete_comment/<int:comment_id>')
@login_required
def delete_comment(comment_id):
    comment = Comment.query.get_or_404(comment_id)
    club_id = comment.book.club_id
    if (comment.user_id == current_user.id or 
        current_user.is_admin or 
        has_role(club_id, ['president', 'moderator'])):
        db.session.delete(comment)
        db.session.commit()
        flash("Comment deleted.", "info")
        create_notification(comment.user_id, f"Your comment on '{comment.book.title}' has been deleted.")
    else:
        flash("You do not have permission to delete this comment.", "danger")
    return redirect(request.referrer or url_for('dashboard'))

@app.route('/confirm/<token>')
def confirm_email(token):
    try:
        email = serializer.loads(token, salt='email-confirm-salt', max_age=3600)
    except:
        flash('The confirmation link is invalid or has expired.', 'danger')
        return redirect(url_for('login'))

    user = User.query.filter_by(email=email).first_or_404()
    if user.is_verified:
        flash('Account already confirmed. Please login.', 'success')
    else:
        user.is_verified = True
        db.session.commit()
        flash('You have confirmed your account. Thanks!', 'success')
    return redirect(url_for('login'))

@app.route('/profile')
@login_required
def profile():
    user = current_user
    joined_memberships = ClubMember.query.filter_by(user_id=user.id).all()
    joined_clubs = [m.club for m in joined_memberships]
    comments = Comment.query.filter_by(user_id=user.id).order_by(Comment.timestamp.desc()).all()
    created_clubs = Club.query.filter_by(creator_id=user.id).all()

    return render_template('profile.html', user=user, joined_clubs=joined_clubs, comments=comments, created_clubs=created_clubs)

@app.route('/profile/<int:user_id>')
@login_required
def view_profile(user_id):
    user = User.query.get_or_404(user_id)
    joined_memberships = ClubMember.query.filter_by(user_id=user.id).all()
    joined_clubs = [m.club for m in joined_memberships]
    comments = Comment.query.filter_by(user_id=user.id).order_by(Comment.timestamp.desc()).all()
    created_clubs = Club.query.filter_by(creator_id=user.id).all()  # ✅ EKLİ

    return render_template('profile.html', user=user, joined_clubs=joined_clubs, comments=comments, created_clubs=created_clubs)

@app.route('/admin')
@admin_required
def admin_dashboard():
    users = User.query.all()
    clubs = Club.query.all()
    return render_template('admin_dashboard.html', users=users, clubs=clubs)

@app.route('/admin/delete_user/<int:user_id>')
@admin_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.is_admin:
        flash("You cannot delete an admin.")
        return redirect(url_for('admin_dashboard'))

    Comment.query.filter_by(user_id=user.id).delete()
    JoinRequest.query.filter_by(user_id=user.id).delete()
    ClubMember.query.filter_by(user_id=user.id).delete()

    for club in user.clubs:
        db.session.delete(club)

    db.session.delete(user)
    db.session.commit()
    flash("User deleted.")
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/delete_club/<int:club_id>')
@admin_required
def delete_club_admin(club_id):
    club = Club.query.get_or_404(club_id)
    db.session.delete(club)
    db.session.commit()
    flash("Club deleted.")
    return redirect(url_for('admin_dashboard'))

if __name__ == '__main__':
    with app.app_context():
        if not os.path.exists('bookie.db'):
            db.create_all()
    app.run(debug=True, port=5001)

