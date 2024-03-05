from flask import Flask, render_template, request, redirect, url_for, session
from flask_mail import Mail, Message
from bs4 import BeautifulSoup
import requests
from newspaper import Article
import nltk
from nltk.tokenize import sent_tokenize, word_tokenize
from nltk import pos_tag
import psycopg2
import json
from random import randint
import datetime
from nltk.corpus import stopwords
from authlib.integrations.flask_client import OAuth
import re

app = Flask(__name__)
mail = Mail(app)
oauth = OAuth(app)

app.secret_key = 'This is secret'

# github
app.config['SECRET_KEY'] = "THIS SHOULD BE SECRET"
app.config['GITHUB_CLIENT_ID'] = "ff2a9c4a4abf7eb1cc8a"
app.config['GITHUB_CLIENT_SECRET'] = "389817d58b1c506cd1684ac45c83ea0a526c89b6"

github = oauth.register(
    name='github',
    client_id=app.config["GITHUB_CLIENT_ID"],
    client_secret=app.config["GITHUB_CLIENT_SECRET"],
    access_token_url='https://github.com/login/oauth/access_token',
    access_token_params=None,
    authorize_url='https://github.com/login/oauth/authorize',
    authorize_params=None,
    api_base_url='https://api.github.com/',
    client_kwargs={'scope': 'user:email'},
)

# GitHub admin usernames for verification
github_admin_usernames = ["skddl005", "skddl005", "atmabodha"]

# Password for accessing history
ADMIN_PASSWORD = "Sandeep123"

# OTP generation for email verification
otp = None

# Sender's name for the email
sender_name = "Sandeep Kumar"

# List of admin email addresses
admin_emails = ["su-23036@sitare.org", "saneeipk@gmail.com", "kushal@sitare.org"]

# PostgreSQL database connection details
DB_NAME = "flask_data"
DB_USER = "postgres"
DB_PASSWORD = "Skd6397@@"
DB_HOST = "localhost"

# Flask-Mail configuration
app.config["MAIL_SERVER"] = 'smtp.gmail.com'
app.config["MAIL_PORT"] = 465
app.config["MAIL_USERNAME"] = 'saneeipk@gmail.com'  # Update with your Gmail email
app.config['MAIL_PASSWORD'] = 'vtraaffusxqpruyp'  # Update with your Gmail password
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True

# mail = Mail(app)

# Initialize NLTK stopwords
nltk.download('stopwords')
stop_words = set(stopwords.words('english'))

# Function to count stop words in text
def count_stop_words(text):
    words = text.split()
    stop_words_count = sum(1 for word in words if word.lower() in stop_words)
    return stop_words_count

def extract_keywords(article_text):
    words = re.findall(r'\b\w+\b', article_text.lower())
    keywords = [word for word in words if word not in stop_words and len(word) > 2]
    return keywords[:10]


def extract_text_from_url(url):
    try:
        article = Article(url)
        article.download()
        article.parse()
        return article.text, article.title, article.keywords, article.publish_date
    except Exception as e:
        return str(e), None, None, None

def save_to_database(url, article_name, article_keywords, text, num_sentences, num_words, upos_count, stop_words_count, published_date):
    conn = psycopg2.connect(dbname=DB_NAME, user=DB_USER, password=DB_PASSWORD, host=DB_HOST)
    cur = conn.cursor()
    cur.execute("INSERT INTO news_data (url, article_name, article_keywords, text, num_sentences, num_words, upos_count, stop_words_count, published_date) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)",
                (url, article_name, json.dumps(article_keywords), text, num_sentences, num_words, json.dumps(upos_count), stop_words_count, published_date))
    conn.commit()
    conn.close()

def get_history_from_database():
    conn = psycopg2.connect(dbname=DB_NAME, user=DB_USER, password=DB_PASSWORD, host=DB_HOST)
    cur = conn.cursor()
    cur.execute("SELECT * FROM news_data")
    data = cur.fetchall()
    conn.close()
    return data

@app.route('/')
def index():
    return render_template('index.html')
    # return render_template('index.html', logged_in=github_token is not None, is_admin=is_admin)

@app.route('/submit', methods=['POST'])
def submit():
    url = request.form['url']
    try:
        article_text, article_name, _, published_date = extract_text_from_url(url)
        if published_date is None:
            published_date = datetime.datetime.now().strftime("%Y-%m-%d")
        else:
            published_date = published_date.strftime("%Y-%m-%d")

        num_sentences = len(sent_tokenize(article_text))
        num_words = len(word_tokenize(article_text))
        upos_tags = nltk.pos_tag(word_tokenize(article_text), tagset='universal')

        upos_count = {}
        for word, pos in upos_tags:
            if pos in upos_count:
                upos_count[pos] += 1
            else:
                upos_count[pos] = 1

        stop_words_count = count_stop_words(article_text)
        article_keywords = extract_keywords(article_text)
        
        save_to_database(url, article_name, article_keywords, article_text, num_sentences, num_words, upos_count, stop_words_count, published_date)
        
        return render_template('dashboard.html', num_sentences=num_sentences, num_words=num_words, upos_count=upos_count, stop_words_count=stop_words_count, published_date=published_date, article_name=article_name, article_keywords=article_keywords)
    except Exception as e:
        return str(e)
    
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        password = request.form['password']
        if password == ADMIN_PASSWORD:
            session['logged_in'] = True
            return redirect(url_for('history'))
        else:
            return "Invalid password. Please try again."
    return render_template('index.html')

@app.route('/otp_login', methods=['GET', 'POST'])
def otp_login():
    if request.method == 'POST':
        global otp
        user_otp = request.form['otp']
        email = session.get('email')
        if otp and otp == int(user_otp) and email in admin_emails:
            session['logged_in'] = True
            return redirect(url_for('history'))
        else:
            return "You are not admin."
    return render_template('otp_login.html')

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('index'))

@app.route('/history')
def history():
    if 'logged_in' in session:
        data = get_history_from_database()
        return render_template('history.html', data=data, logged_in=True)
    else:
        return redirect(url_for('login'))

@app.route('/send_otp', methods=["POST"])
def send_otp():
    global otp
    email = request.form['email']
    otp = randint(100000, 999999)
    msg = Message(subject='OTP', sender=('Sandeep Kumar', app.config["MAIL_USERNAME"]), recipients=[email])
    msg.body = f'Your OTP is: {otp}'
    try:
        mail.send(msg)
        session['email'] = email
        return render_template('otp_login.html', otp_sent=True)  # Redirect to OTP login page
    except Exception as e:
        return str(e)
    
    

@app.route('/login/github')
def github_login():
    github = oauth.create_client('github')
    redirect_uri = url_for('github_authorize', _external=True)
    return github.authorize_redirect(redirect_uri)

# Github authorize route
@app.route('/login/github/authorize')
def github_authorize():
    try:
        github = oauth.create_client('github')
        token = github.authorize_access_token()
        session['github_token'] = token
        resp = github.get('user').json()
        print(f"\n{resp}\n")
        # print(type(repr))
        # data=get_history_from_database()
        # return render_template("history.html",data=data)
        logged_in_username = resp.get('login')
        if logged_in_username in github_admin_usernames:
            data = get_history_from_database()
            return render_template("history.html", data=data)
        else:
            return redirect(url_for('index'))
    except:
        return redirect(url_for('index'))

    
# Logout route for GitHub
@app.route('/logout/github')
def github_logout():
    session.clear()
    # session.pop('github_token', None)()
    print("logout")
    # return redirect(url_for('index'))
    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run(debug=True)
