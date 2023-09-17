import os
import smtplib
from datetime import date
from flask import Flask, abort, render_template, redirect, url_for, flash, request, g
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
# from flask_gravatar import Gravatar
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user, login_required
from flask_sqlalchemy import SQLAlchemy
# from flask_migrate import Migrate
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
# from sqlalchemy.orm import relationship, Mapped, mapped_column, DeclarativeBase
# from sqlalchemy import ForeignKey, Integer
# from typing import List
# # Import your forms from the forms.py
from forms import *

'''
Make sure the required packages are installed: 
Open the Terminal in PyCharm (bottom left). 

On Windows type:
python -m pip install -r requirements.txt

On MacOS type:
pip3 install -r requirements.txt

This will install the packages from the requirements.txt for this project.
'''

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('FLASK_KEY')
ckeditor = CKEditor(app)
Bootstrap5(app)

# TODO: Configure Flask-Login - DONE
login_manager = LoginManager()
login_manager.init_app(app)

# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DU_URI', 'sqlite:///posts.db')
db = SQLAlchemy()
db.init_app(app)


# CONFIGURE TABLES
class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(250), unique=True, nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    author = db.Column(db.String(250), nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)

    # ****************adding relationships************************

    # **********adding many blog_posts with one user**************
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    post_author = db.relationship("User", back_populates="user_posts")

    # ******this is adding many comments wwith one blog_post******
    post_comments = db.relationship("Comment", back_populates="blog_comments")


# TODO: Create a User table for all your registered users.
class User(db.Model, UserMixin):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(250), unique=False, nullable=False)
    email = db.Column(db.String(250), unique=True, nullable=False)
    password = db.Column(db.String(250), unique=False, nullable=False)

    # ****************adding relationships************************

    # *******adding relationship many blog_posts to one user******
    user_posts = db.relationship("BlogPost", back_populates="post_author")

    # ************adding many comments with one user**************
    user_comments = db.relationship("Comment", back_populates="comment_author")


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    comment = db.Column(db.String(1000), unique=False, nullable=False)

    # ****************adding relationships************************

    # ***********adding many comments to one blog_post************
    blog_id = db.Column(db.Integer, db.ForeignKey('blog_posts.id'))
    blog_comments = db.relationship("BlogPost", back_populates="post_comments")

    # *************adding many comments to one user***************
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    comment_author = db.relationship("User", back_populates="user_comments")


def create_tables():
    with app.app_context():
        db.create_all()


@login_manager.user_loader
def user_loader(user):
    return db.get_or_404(User, user)


@app.route('/')
def home():
    posts = BlogPost.query.all()
    return render_template('index.html', posts=posts)


def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for('login'))
        if current_user.id != 1:
            return abort(403)
        return f(*args, **kwargs)

    return decorated_function


# TODO: Use Werkzeug to hash the user's password when creating a new user.
@app.route('/register', methods=["POST", "GET"])
def register():
    form = RegisterForm()
    if request.method == "POST":
        exists = db.session.query(User.email).filter_by(email=request.form.get('email')).scalar() is not None
        if exists and not current_user.is_authenticated:
            flash(f'The user {request.form.get("full_name")} already exists.\nplease login')
            return redirect(url_for('login'))
        if exists and current_user.is_authenticated:
            return redirect(url_for('home'))
        if not current_user.is_authenticated:
            email = request.form.get('email')
            name = request.form.get('full_name')
            raw_password = request.form.get('password')
            hash_password = generate_password_hash(raw_password, method="pbkdf2:sha256", salt_length=8)
            new_user = User(
                name=name,
                password=hash_password,
                email=email
            )
            db.session.add(new_user)
            db.session.commit()
            user_loader(new_user.id)
            login_user(new_user)
            return redirect(url_for('home'))
        else:
            flash(f'{current_user.name} is already logged in.\nplease logout to create a new account')
            return redirect(url_for('home'))

    return render_template("register.html", form=form)


# TODO: Retrieve a user from the database based on their email. 
@app.route('/login', methods=["POST", "GET"])
def login():
    form = LoginForm()
    error_message = None
    if request.method == "POST" and not current_user.is_authenticated:
        email = request.form.get('email')
        password = request.form.get('password')
        exists = db.session.query(User.email).filter_by(email=email).scalar() is not None
        if exists:
            my_pal = User.query.where(User.email == email).scalar()
            user_loader(my_pal.id)
            login_user(my_pal)
            flash(f'{my_pal.name} has successfully logged in')
            return redirect(url_for('home'))
        else:
            error_message = f"the user {email} doesn't exist"
    return render_template("login.html", error_message=error_message, form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route('/')
def get_all_posts():
    result = db.session.execute(db.select(BlogPost))
    posts = result.scalars().all()
    return render_template("index.html", all_posts=posts)


# TODO: Allow logged-in users to comment on posts
@app.route("/post/<int:post_id>", methods=["POST", "GET"])
def show_post(post_id):
    form = CommentForm()
    if request.method == "POST" and not current_user.is_authenticated:
        flash("You must be logged in to comment.")
        return redirect(url_for('login'))
    elif request.method == "POST" and current_user.is_authenticated:
        new_comment = Comment(
            comment=request.form.get('comment'),
            blog_id=post_id,
            user_id=current_user.id
        )
        db.session.add(new_comment)
        db.session.commit()
    requested_post = db.get_or_404(BlogPost, post_id)
    comments = Comment.query.all()
    return render_template("post.html", post=requested_post, form=form, comments=comments)


# TODO: Use a decorator so only an admin user can create a new post
@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user.name,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


# TODO: Use a decorator so only an admin user can edit a post
@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
def edit_post(post_id):
    post = db.get_or_404(BlogPost, post_id)
    edit_form = CreatePostForm(
        author=post.author,
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        body=post.body
    )
    if request.method == "POST":
        if edit_form.validate_on_submit():
            post.title = edit_form.title.data
            post.subtitle = edit_form.subtitle.data
            post.img_url = edit_form.img_url.data
            post.body = edit_form.body.data
            post.author = edit_form.author.data
            db.session.commit()
            return redirect(url_for("show_post", post_id=post.id))
    return render_template("make-post.html", form=edit_form, is_edit=True)


# TODO: Use a decorator so only an admin user can delete a post
@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = db.get_or_404(BlogPost, post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


@app.route("/about")
def about():
    return render_template("about.html")

@app.route("/contact", methods=['POST', 'GET'])
def contact():
    if request.method == 'POST':
        message = request.form.get('message')
        phone = request.form.get('phone')
        email = request.form.get('email')
        name = request.form.get('name')
        my_email = os.environ.get('MY_EMAIL')
        password = os.environ.get('MY_EMAIL_PASSWORD')
        with smtplib.SMTP("smtp.gmail.com", 587) as connection:
            connection.starttls()
            connection.login(user=my_email, password=password)
            connection.sendmail(
                from_addr=my_email,
                to_addrs='mjcolyer@gmail.com',
                msg=f'Subject:Message From your Blog\n\n from: {name}\nemail: {email}\nphone: {phone}\n-----------\n{message}'
            )
        flash('Your message has been sent. Thanks for your input')
        return redirect(url_for('home'))
    return render_template("contact.html")


if __name__ == "__main__":
    create_tables()
    app.run(debug=False, port=5002)
