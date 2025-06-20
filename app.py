from flask import Flask, render_template, redirect, url_for, request, flash, session, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os, random, string
from datetime import datetime
from werkzeug.utils import secure_filename

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


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    clubs = db.relationship('Club', backref='creator', lazy=True)
    comments = db.relationship('Comment', backref='author', lazy=True)

class Club(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    code = db.Column(db.String(6), unique=True, nullable=False)
    image = db.Column(db.String(200))
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    books = db.relationship('Book', backref='club', lazy=True, cascade="all, delete-orphan")
    members = db.relationship('ClubMember', backref='club', lazy=True, cascade="all, delete-orphan")

class ClubMember(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    club_id = db.Column(db.Integer, db.ForeignKey('club.id'), nullable=False)

class Book(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    image = db.Column(db.String(200))
    club_id = db.Column(db.Integer, db.ForeignKey('club.id'), nullable=False)
    comments = db.relationship('Comment', backref='book', lazy=True, cascade="all, delete-orphan")

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    book_id = db.Column(db.Integer, db.ForeignKey('book.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

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
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)
        new_user = User(username=username, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful! Please log in.')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
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

@app.route('/create_club', methods=['GET', 'POST'])
@login_required
def create_club():
    if request.method == 'POST':
        name = request.form['name']
        image = request.files['image']
        filename = None
        if image and allowed_file(image.filename):
            filename = secure_filename(image.filename)
            image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        new_club = Club(name=name, code=generate_code(), image=filename, creator_id=current_user.id)
        db.session.add(new_club)
        db.session.commit()
        if not ClubMember.query.filter_by(user_id=current_user.id, club_id=new_club.id).first():
            member = ClubMember(user_id=current_user.id, club_id=new_club.id)
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
        if club:
            if not ClubMember.query.filter_by(user_id=current_user.id, club_id=club.id).first():
                db.session.add(ClubMember(user_id=current_user.id, club_id=club.id))
                db.session.commit()
            return redirect(url_for('dashboard'))
        flash('Invalid code.')
    return render_template('join_club.html')

@app.route('/club/<int:club_id>', methods=['GET', 'POST'])
@login_required
def club_detail(club_id):
    club = Club.query.get_or_404(club_id)
    is_president = current_user.id == club.creator_id
    books = Book.query.filter_by(club_id=club.id).all()
    members = ClubMember.query.filter_by(club_id=club.id).all()
    usernames = [User.query.get(m.user_id).username for m in members]
    return render_template('club_detail.html', club=club, is_president=is_president, books=books, usernames=usernames)

@app.route('/add_book/<int:club_id>', methods=['POST'])
@login_required
def add_book(club_id):
    club = Club.query.get_or_404(club_id)
    if current_user.id != club.creator_id:
        flash('Only the club president can add books.')
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
    return redirect(url_for('club_detail', club_id=club_id))

@app.route('/delete_club/<int:club_id>')
@login_required
def delete_club(club_id):
    club = Club.query.get_or_404(club_id)
    if current_user.id == club.creator_id:
        db.session.delete(club)
        db.session.commit()
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
    return redirect(request.referrer or url_for('dashboard'))

@app.route('/delete_comment/<int:comment_id>')
@login_required
def delete_comment(comment_id):
    comment = Comment.query.get_or_404(comment_id)
    if comment.user_id == current_user.id:
        db.session.delete(comment)
        db.session.commit()
    return redirect(request.referrer or url_for('dashboard'))

if __name__ == '__main__':
    app.run(debug=True, port=5001)
    #app.run(debug=True)
