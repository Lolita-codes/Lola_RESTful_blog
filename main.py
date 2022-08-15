import datetime
import smtplib
import ssl
from functools import wraps
from flask import Flask, render_template, redirect, url_for, flash, abort, request
from flask_bootstrap import Bootstrap
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_ckeditor import CKEditor
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from flask_gravatar import Gravatar
import os
from dotenv import load_dotenv
load_dotenv('.env')

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
ckeditor = CKEditor(app)
Bootstrap(app)

# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL", "sqlite:///posts.db")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
current_year = datetime.datetime.now().year


login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


gravatar = Gravatar(app,
                    size=30,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)


class User(UserMixin, db.Model):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(100))
    # This will act like a List of BlogPost objects attached to each User.
    # The "author" refers to the author property in the BlogPost class.
    posts = relationship("BlogPost", back_populates="author")
    comments = relationship('Comment', back_populates='comment_author')


# CONFIGURE TABLE
class BlogPost(db.Model):
    __tablename__ = "blog_post"
    id = db.Column(db.Integer, primary_key=True)
    # Creates Foreign Key
    author_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    # References the User object and posts in the User class.
    author = relationship("User", back_populates="posts")
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    comments = relationship('Comment', back_populates='parent_post')


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer, db.ForeignKey("blog_post.id"))
    author_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    comment_author = relationship("User", back_populates="comments")
    parent_post = relationship("BlogPost", back_populates="comments")
    text = db.Column(db.Text, nullable=False)
db.create_all()


# Creates admin-only decorator
def admin_only(f):
    @wraps(f)
    # Returns 403 error if id is not 1, i.e not admin, continue with route otherwise
    def decorated_function(*args, **kwargs):
        if current_user.id != 1:
            return abort(403)
        return f(*args, **kwargs)
    return decorated_function


# Gets Blog posts items
@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts, year=current_year, logged_in=current_user.is_authenticated, current_user=current_user)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        email = form.email.data
        user = User.query.filter_by(email=email).first()
        # User already exists
        if user:
            flash('You\'ve already signed up with that email, log in instead!')
            return redirect(url_for('login'))
        hashed_and_salted_password = generate_password_hash(form.password.data,
                                                            method='pbkdf2:sha256',
                                                            salt_length=8)
        new_user = User()
        new_user.email = form.email.data
        new_user.name = form.name.data
        new_user.password = hashed_and_salted_password
        db.session.add(new_user)
        db.session.commit()
        # Log in and authenticate user after adding details to database.
        login_user(new_user)
        return redirect(url_for('get_all_posts'))
    return render_template("register.html", form=form, logged_in=current_user.is_authenticated)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        # Find user by email entered.
        user = User.query.filter_by(email=email).first()
        # Email doesn't exist
        if not user:
            flash('That email does not exist, please try again.')
        # Check stored password hash against entered password hashed.
        elif not check_password_hash(user.password, password):
            flash('Password incorrect, please try again.')
        # Email exists and password correct
        else:
            login_user(user)
            return redirect(url_for('get_all_posts'))

    return render_template("login.html", form=form, logged_in=current_user.is_authenticated)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:index>", methods=["GET", "POST"])
def show_post(index):
    all_comments = Comment.query.filter_by(post_id=index).all()
    form = CommentForm()
    requested_post = BlogPost.query.get(index)
    if form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("You need to login or register to comment.")
            return redirect(url_for("login"))
        new_comment = Comment(
            text=form.comment.data,
            comment_author=current_user,
            parent_post=requested_post
        )
        db.session.add(new_comment)
        db.session.commit()
    return render_template("post.html", post=requested_post, year=current_year, form=form, comments=all_comments,
                           current_user=current_user, logged_in=current_user.is_authenticated)


@app.route("/about")
def about():
    return render_template("about.html", year=current_year)


@app.route("/contact", methods=["GET", "POST"])
def contact():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        phone_number = request.form.get('phone_number')
        message = request.form.get('message')
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL('smtp.gmail.com', 465, context=context) as connection:
            connection.login(user=os.environ['EMAIL'], password=os.environ['PASSWORD'])
            connection.sendmail(
                from_addr=os.environ['EMAIL'],
                to_addrs=os.environ['TO_EMAIL'],
                msg=f"Subject: New Message\n\nName: {name}\nEmail address: {email}\nPhone Number: {phone_number}\nMessage: {message}"
            )
        flash('Thank you. I will reply as soon as possible')
        return redirect(url_for('contact'))
    return render_template("contact.html", year=current_year)


# Post a new blog post
@app.route('/new-post', methods=['GET', 'POST'])
@admin_only
def create_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            date=datetime.date.today().strftime('%B %d, %Y'),
            body=form.body.data,
            author=current_user,
            img_url=form.img_url.data,
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for('get_all_posts'))
    return render_template('make-post.html', form=form, year=current_year, current_user=current_user)


# Edits existing blog posts
@app.route('/edit-post/<post_id>', methods=['GET', 'POST'])
@admin_only
def edit_post(post_id):
    post_to_update = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post_to_update.title,
        subtitle=post_to_update.subtitle,
        img_url=post_to_update.img_url,
        author=post_to_update.author,
        body=post_to_update.body
    )
    if edit_form.validate_on_submit():
        post_to_update.title = edit_form.title.data
        post_to_update.subtitle = edit_form.subtitle.data
        post_to_update.img_url = edit_form.img_url.data
        post_to_update.author = current_user
        post_to_update.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", index=post_to_update.id))
    return render_template('make-post.html', form=edit_form, to_edit=True, year=current_year, logged_in=current_user.is_authenticated)


@app.route('/delete/<post_id>')
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(debug=True)