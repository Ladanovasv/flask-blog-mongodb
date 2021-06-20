from sys import path
from flask import flash, redirect, session
from flask import Flask, render_template, request, url_for, send_from_directory
#from data import Articles
from flask_ckeditor import CKEditorField
from wtforms import Form, StringField, TextAreaField, PasswordField, validators
from passlib.hash import sha256_crypt
from functools import wraps
import pymongo
from flask_ckeditor import CKEditor

from bson.objectid import ObjectId
import os
from flask_ckeditor import CKEditor, CKEditorField, upload_fail, upload_success

from flask_wtf import FlaskForm, form
from wtforms.validators import DataRequired
from flask_wtf.file import FileField, FileAllowed, FileRequired
from werkzeug.utils import secure_filename


basedir = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)
app.config['CKEDITOR_SERVE_LOCAL'] = True
app.config['CKEDITOR_HEIGHT'] = 400
app.config['CKEDITOR_FILE_UPLOADER'] = 'upload'
# app.config['CKEDITOR_ENABLE_CSRF'] = True  # if you want to enable CSRF protect, uncomment this line
app.config['UPLOADED_PATH'] = os.path.join(basedir, 'uploads')
app.config['UPLOAD_FOLDER'] = 'uploads/'
# csrf = CSRFProtect(app)
app.secret_key = 'secret string'



ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg', 'gif'])

def allowed_file(filename):
	return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
ckeditor = CKEditor(app)

CONNECTION_STRING = "mongodb://localhost"  # replace it with your settings
CONNECTION = pymongo.MongoClient(CONNECTION_STRING)

'''Leave this as is if you dont have other configuration'''
DATABASE = CONNECTION.flask_blog
POSTS_COLLECTION = DATABASE.posts
USERS_COLLECTION = DATABASE.users
FILES_COLLECTION = DATABASE.files

SECRET_KEY = ""


#Articles = Articles()

# Index
@app.route('/')
def index():
    posts = POSTS_COLLECTION.find()
    return render_template('home.html', posts=posts)


# About
@app.route('/about')
def about():
    return render_template('about.html')


# Articles
@app.route('/articles')
def articles():
    articles = list( POSTS_COLLECTION.find({}) )

    if len(articles) > 0:
        return render_template('articles.html', articles=articles)
    else:
        msg = 'No Articles Found'
        return render_template('articles.html', msg=msg)
    


#Single Article
@app.route('/article/<string:slug>/', methods=['GET'])
def article(slug):
    article = POSTS_COLLECTION.find_one({"slug": slug}) 
    return render_template('article.html', article=article)


# Register Form Class
class RegisterForm(Form):
    name = StringField('Name', [validators.Length(min=1, max=50)], render_kw={"placeholder": "name"})
    username = StringField('Username', [validators.Length(min=4, max=25)], render_kw={"placeholder": "username"})
    email = StringField('Email', [
        validators.Length(min=6, max=50)], render_kw={"placeholder": "email"})
    password = PasswordField('Password', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Passwords do not match')
    ], render_kw={"placeholder": "password"})
    confirm = PasswordField('Confirm Password', render_kw={"placeholder": "confirm password"})


# User Register
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm(request.form)
    if request.method == 'POST' and form.validate():
        name = form.name.data
        email = form.email.data
        username = form.username.data
        password = sha256_crypt.encrypt(str(form.password.data))

        result = USERS_COLLECTION.insert_one({
            'name': name,
            'email': email,
            'username': username,
            'password': password
        })
        result = os.mkdir(os.path.join( app.config['UPLOADED_PATH'], username))
        flash('You are now registered and can log in', 'success')
        return redirect(url_for('login'))
    return render_template('_register.html', form=form)

class LoginForm(Form):
    username = StringField('Username',  render_kw={"placeholder": "username"})
    password = PasswordField('Password', render_kw={"placeholder": "password"})
    
# User login
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm(request.form)
    if request.method == 'POST':
        # Get Form Fields
        
        username = form.username.data
        password_candidate = form.password.data

        result = list( USERS_COLLECTION.find({"username": username}) )

        if len(result) > 0:
            # Get stored hash
            data = result[0]
            password = data['password']

            # Compare Passwords
            if sha256_crypt.verify(password_candidate, password):
                # Passed
                session['logged_in'] = True
                session['username'] = username

                flash('You are now logged in', 'success')
                return redirect(url_for('dashboard'))
            else:
                error = 'Invalid login'
                return render_template('_login.html', error=error, form=form)
            
        else:
            error = 'Username not found'
            return render_template('_login.html', error=error, form=form)
    return render_template('_login.html', form=form)

# Check if user logged in
def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash('Unauthorized, Please login', 'danger')
            return redirect(url_for('login'))
    return wrap

# Logout
@app.route('/logout')
@is_logged_in
def logout():
    session.clear()
    flash('You are now logged out', 'success')
    return redirect(url_for('login'))

# Dashboard
@app.route('/dashboard')
@is_logged_in
def dashboard():
    articles = list( POSTS_COLLECTION.find({"author": session['username']}) )
    if len(articles) > 0:
        return render_template('dashboard.html', articles=articles)
    else:
        msg = 'No Articles Found'
        return render_template('dashboard.html', msg=msg)


# Article Form Class
class ArticleForm(Form):
    title = StringField('Title', [validators.Length(min=1, max=200)], render_kw={"placeholder": "title"})
    # image = FileField('Image',  render_kw={"placeholder": "image start page"})
    body = CKEditorField('Body', validators=[DataRequired()], render_kw={"placeholder": "body"})
    slug = StringField('Slug', [validators.Length(min=3, max=200)], render_kw={"placeholder": "slug"})

# Add Article
@app.route('/add_article', methods=['GET', 'POST'])
@is_logged_in
def add_article():
    form = ArticleForm(request.form)
    if request.method == 'POST' and form.validate():
        title = form.title.data
        body = form.body.data
        slug = form.slug.data

        if 'file' not in request.files:
            # print('No file part')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            path = os.path.join( os.path.join( app.config['UPLOADED_PATH'], session['username']), filename)
            file.save(path)
            flash('Image successfully uploaded and displayed below')
            result = FILES_COLLECTION.insert_one({'path': path})
            hash = FILES_COLLECTION.find_one({"path": path})
            result = POSTS_COLLECTION.insert({
                'title': title,
                'body': body,
                'slug': slug,
                'image': hash['_id'],
                'author': session['username']
            })

            flash('Article Created', 'success')

            return redirect(url_for('dashboard'))
        else:
            flash('Allowed image types are -> png, jpg, jpeg, gif')
            return redirect(request.url)

    return render_template('add_article.html', form=form)


# Edit Article
@app.route('/edit_article/<string:slug>', methods=['GET', 'POST'])
@is_logged_in
def edit_article(slug):
    article = list( POSTS_COLLECTION.find({"slug": slug}) ) 
    form = ArticleForm(request.form)

    # Populate article form fields
    form.title.data = article[0]['title']
    form.body.data = article[0]['body']

    if request.method == 'POST':
        title = request.form['title']
        body = request.form['body']

        post_data = {
            'title': title,
            'body': body
        }
        result = POSTS_COLLECTION.update(
                {'slug': slug }, {"$set": post_data}, upsert=False)

        flash('Article Updated', 'success')

        return redirect(url_for('dashboard'))

    return render_template('edit_article.html', form=form)

# Delete Article
@app.route('/delete_article/<string:slug>', methods=['POST'])
@is_logged_in
def delete_article(slug):
    result = POSTS_COLLECTION.delete_one(
                {'slug': slug} )

    flash('Article Deleted', 'success')

    return redirect(url_for('dashboard'))


@app.route('/files/<filename>')
def uploaded_files(filename):
    hash = FILES_COLLECTION.find_one({"_id": ObjectId(filename)})
    user, file = hash['path'].split('/')[-2:]
    path = os.path.join(app.config['UPLOADED_PATH'], user)
    return send_from_directory(path, file)


@app.route('/upload', methods=['POST'])
def upload():
    f = request.files.get('upload')
    extension = f.filename.split('.')[-1].lower()
    if extension not in ['jpg', 'gif', 'png', 'jpeg']:
        return upload_fail(message='Image only!')
    path = os.path.join( os.path.join( app.config['UPLOADED_PATH'], session['username']), f.filename)
    
    result = FILES_COLLECTION.insert_one({'path': path})
    f.save(path) 
    hash = FILES_COLLECTION.find_one({"path": path})
    
    url = url_for('uploaded_files', filename=hash['_id'])
    return upload_success(url=url)
 





if __name__ == '__main__':
    app.run(debug=True)
