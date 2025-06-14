
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from pymongo import MongoClient
from bson.objectid import ObjectId, InvalidId
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime
import requests
from huggingface_hub import InferenceClient

app = Flask(__name__, static_folder='static', template_folder='templates')

app.secret_key = "supersecretkey"

client = MongoClient("mongodb://localhost:27017")

db = client.testenv
users = db.users
reviews = db.reviews
movies = db.movies
watchlists = db.watchlists

dbreview = client.movie_reviews
review_collection = dbreview.reviews

TMDB_API_KEY = "d32e627249c8e914b19484ffe655f6d6"

# INTRO PAGE
@app.route('/')
def intro():
    return render_template('intro.html')

# HOMEPAGE
@app.route('/home')
def home():
    username = session.get('username', 'Sign up/Login') 
    return render_template('home.html', username=username)

# ABOUT US PAGE
@app.route('/aboutus')
def aboutus():
    # Optioneel: Je kunt de username doorgeven als je die in de aboutus pagina wilt weergeven
    username = session.get('username', 'Sign up/Login') 
    return render_template('aboutus.html', username=username)

# USER SEARCH APP ROUTES
@app.route('/usersearch', methods=['GET'])
def usersearch_page():
    return render_template('usersearch.html')

## SEARCH USERS FROM DATABASE
@app.route('/search_users', methods=['GET'])
def search_users():
    query = request.args.get('q', '')
    results = []

    if query:
        users_list = users.find({
            "username": {"$regex": query, "$options": "i"}
        })

        for user in users_list:
            results.append({
                "username": user.get("username", "N/A")
            })

    return jsonify(results)

## USER VIEW PAGE
@app.route('/view_user/<username>')
def view_user(username):
    user = users.find_one({"username": username})

    if not user:
        return "User not found", 404

    return render_template('userview.html', user=user)

# MOVIE SEARCH PAGE
@app.route('/search')
def search():
    return render_template('search.html')

# LOGIN PAGE 
@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'logged_in' in session and session['logged_in']:
        return redirect(url_for('home'))

    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = users.find_one({'email': email})

        if user and 'password' in user and check_password_hash(user['password'], password):
            session['logged_in'] = True
            session['username'] = user['username']
            flash('Successfully logged in!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid login credentials. Please check your email and password.', 'danger')
            return render_template('login.html', email=email) 

    return render_template('login.html')

# SIGN UP PAGE
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if 'logged_in' in session and session['logged_in']:
        return redirect(url_for('home'))

    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if not username or not email or not password or not confirm_password:
            flash('Please fill in all fields.', 'warning')
            return render_template('signup.html', username=username, email=email)
        
        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('signup.html', username=username, email=email)
        
        if users.find_one({'email': email}):
            flash('This email address is already registered. Try logging in.', 'warning')
            return render_template('signup.html', username=username, email=email)
        
        hashed_password = generate_password_hash(password)

        new_user = {
            'username': username,
            'email': email,
            'password': hashed_password,
            'created': datetime.utcnow(), 
            'bio': 'Movie Newbie',   
            'role': 'user'
        }

        users.insert_one(new_user)
        
        flash('Account successfully created! You are now logged in.', 'success')
        session['logged_in'] = True
        session['username'] = username 
        
        return redirect(url_for('home')) 

    return render_template('signup.html')

# LOGOUT APP ROUTE
@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    session.pop('username', None)
    flash('You have been logged out.', 'info') # Translated flash message
    return redirect(url_for('home'))

# MOVIE REVIEWS

@app.route('/reviews/<int:movie_id>')
def reviewpage():
    return render_template('reviewpage.html')

# USER PAGE
## GET USER
@app.route('/userpage')
def userpage():
    if 'logged_in' not in session or not session['logged_in']:
        return redirect(url_for('login'))
    
    user = users.find_one({"username": session['username']})

    if not user:
        return render_template("404.html", message="User not found"), 404

    user['_id'] = str(user['_id'])

    user_reviews = list(reviews.find({"username": user['username']}))

    user_watchlists = list(watchlists.find({"username": user['username']}))

    return render_template('userpage.html', user=user, watchlists=user_watchlists, reviews=user_reviews)

## UPDATE OR EDIT REVIEW
@app.route('/reviews/<review_id>/edit', methods=['POST'])
def update_review(review_id):
    data = request.json
    reviews.update_one(
        {"_id": ObjectId(review_id)},
        {"$set": {
            "rating": float(data.get("rating")),
            "reviewText": data.get("reviewText")
        }}
    )
    return jsonify({"message": "Review updated"}), 200

## DELETE REVIEW
@app.route('/reviews/<review_id>/delete', methods=['POST'])
def delete_review(review_id):
    result = reviews.delete_one({"_id": ObjectId(review_id)})
    if result.deleted_count:
        return jsonify({"message": "Review deleted"}), 200
    return jsonify({"error": "Review not found"}), 404

## REMOVE WATCHLIST MOVIEE
@app.route('/watchlists/<watchlist_id>/remove', methods=['POST'])
def remove_from_watchlist(watchlist_id):
    result = watchlists.delete_one({"_id": ObjectId(watchlist_id)})
    if result.deleted_count:
        return jsonify({"message": "Watchlist movie removed"}), 200
    return jsonify({"error": "Watchlist movie not found"}), 404

## UPDATE USER BIO
@app.route('/users/<user_id>', methods=['PUT'])
def update_user(user_id):
    data = request.json
    update_result = users.update_one(
        {"_id": ObjectId(user_id)},
        {"$set": {"bio": data.get("bio", "")}}
    )
    if update_result.matched_count:
        return jsonify({"message": "User updated"})
    return jsonify({"error": "User not found"}), 404

## DELETE ACCOUNT
@app.route('/delete_account', methods=['POST'])
def delete_account():
    if 'logged_in' not in session or not session['logged_in']:
        flash("You are not logged in.", "danger")
        return redirect(url_for('login'))

    username = session.get('username')

    users.delete_one({'username': username})

    reviews.delete_many({'username': username})
    watchlists.delete_many({'username': username})

    session.clear()

    flash("Your account has been successfully deleted.", "success")

    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)
