
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from pymongo import MongoClient
from bson.objectid import ObjectId , InvalidId
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime
import requests
from huggingface_hub import InferenceClient

app = Flask(__name__, static_folder='static', template_folder='templates')

app.secret_key = "supersecretkey"

client = MongoClient("mongodb://localhost:27017")

db = client.testenv
users_col = db.users
reviews_col = db.reviews
watchlists_col = db.watchlists

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
        users_list = users_col.find({
            "username": {"$regex": query, "$options": "i"}
        })

        for user in users_list:
            results.append({
                "username": user.get("username", "N/A")
            })

    return jsonify(results)

## USER VIEW PAGE

def get_movie_title_by_id(tmdb_id):
    tmdb_api_key = TMDB_API_KEY  
    url = f"https://api.themoviedb.org/3/movie/{tmdb_id}"
    params = {
        "api_key": tmdb_api_key,
        "language": "en-US"
    }

    try:
        response = requests.get(url, params=params)
        response.raise_for_status()
        movie_data = response.json()
        return movie_data.get("title", "Unknown Title")
    except Exception as e:
        print(f"[TMDB ERROR] Failed to get movie title: {e}")
        return "Unknown Title"

@app.route('/view_user/<username>')
def view_user(username):
    user = users_col.find_one({"username": username})
    if not user:
        return "User not found", 404

    user['_id'] = str(user['_id'])

    reviews = []
    for r in reviews_col.find({"user_id": user['_id']}):
        movie_title = get_movie_title_by_id(r.get("tmdb_id", ""))
        review = {
            "tmdb_id": r.get("tmdb_id"),  
            "movie_title": movie_title,
            "review_title": r.get("review_title", ""),
            "review_text": r.get("review_text", ""),
            "release_date": r.get("release_date", "")[:4],
            "user_rating": r.get("user_rating", 0),
            "created_at": r.get("created_at").strftime("%Y-%m-%d") if r.get("created_at") else "",
            "username": user.get("username", "Unknown")
        }
        reviews.append(review)

    watchlists = list(watchlists_col.find({"username": username}))

    return render_template('userview.html', user=user, reviews=reviews, watchlists=watchlists)


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

        user = users_col.find_one({'email': email})

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
        
        if users_col.find_one({'email': email}):
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

        users_col.insert_one(new_user)
        
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
    flash('You have been logged out.', 'info') 
    return redirect(url_for('home'))


# MOVIE REVIEWS

def get_movie_release_date(tmdb_id):
    tmdb_api_key = TMDB_API_KEY  
    url = f"https://api.themoviedb.org/3/movie/{tmdb_id}"
    params = {
        "api_key": tmdb_api_key,
        "language": "en-US"
    }

    try:
        response = requests.get(url, params=params)
        response.raise_for_status()
        movie_data = response.json()
        return movie_data.get("release_date", "")
    except Exception as e:
        print(f"[TMDB ERROR] Failed to get release date: {e}")
        return ""

@app.route('/reviews/<int:tmdb_id>')
def reviewpage(tmdb_id):
    sentiment_map = {
        "LABEL_0": "Negative",
        "LABEL_1": "Positive",
        "LABEL_2": "Neutral"
    }

    reviews_cursor = reviews_col.find({"tmdb_id": tmdb_id})
    reviews = []

    for r in reviews_cursor:
        user_id = r.get("user_id")
        review_author = "Unknown User"

        if user_id:
            try:
                user = users_col.find_one({"_id": ObjectId(user_id)})
                if user and "username" in user:
                    review_author = user["username"]
            except Exception as e:
                print(f"Invalid user_id: {user_id} - {e}")

        raw_sentiment = r.get("sentiment", "LABEL_UNKNOWN")

        reviews.append({
            "_id": str(r.get("_id")),
            "tmdb_id": r.get("tmdb_id"),
            "review_title": r.get("review_title"),
            "release_date": r.get("release_date", ""),  
            "user_rating": r.get("user_rating"),
            "review_text": r.get("review_text", ""),
            "username": review_author,
            "created_at": r.get("created_at").strftime("%Y-%m-%d") if r.get("created_at") else "",
            "likes": r.get("likes", 0),
            "dislikes": r.get("dislikes", 0),
            "sentiment": sentiment_map.get(raw_sentiment, "Unknown")
        })

    current_user = session.get("username", "Sign up/Login")
    logged_in = bool(session.get("username"))

    return render_template(
        'reviewpage.html',
        reviews=reviews,
        tmdb_id=tmdb_id,
        username=current_user,
        logged_in=logged_in
    )

# Initialize the Hugging Face inference client (only once globally)
client = InferenceClient(api_key="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")

def classify_sentiment(text):
    result = client.text_classification(
        text,
        model="KeonBlackwell/movie_sentiment_model"
    )
    
    score_negtive = 0
    score_positive = 0

    if result[0].label == 'LABEL_0' : 
        score_negtive = result[0].score
        score_positive = result[1].score
    else : 
        score_negtive = result[1].score
        score_positive = result[0].score
    
    if score_negtive > 0.7:
        return "LABEL_0"
    elif score_positive>0.7:
        return "LABEL_1"
    else:
        return "LABEL_2"

@app.route('/submit_review', methods=['POST'])
def submit_review():
    if 'username' not in session:
        return jsonify({"error": "You must be logged in to submit a review."}), 401

    data = request.json
    review_text = data.get("review_text")
    review_title = data.get("review_title")
    tmdb_id = data.get("tmdb_id")
    user_rating = data.get("user_rating")

    if not review_text or not review_title or not tmdb_id or user_rating is None:
        return jsonify({"error": "Missing required fields"}), 400

    # Classify sentiment
    sentiment_label = classify_sentiment(review_text)

    # Get user from session
    user = users_col.find_one({"username": session['username']})
    if not user:
        return jsonify({"error": "User not found"}), 404

    user_id_str = str(user['_id'])  # Convert ObjectId to string

    new_review = {
        "tmdb_id": tmdb_id,
        "review_title": review_title,
        "release_date": get_movie_release_date(tmdb_id),
        "user_rating": float(data.get("user_rating")),
        "review_text": review_text,
        "user_id": user_id_str,
        "created_at": datetime.utcnow(),
        "likes": 0,
        "dislikes": 0,
        "sentiment": sentiment_label
    }

    result = reviews_col.insert_one(new_review)
    return jsonify({"message": "Review submitted", "reviewId": str(result.inserted_id)}), 201


@app.route('/reviews/<review_id>/vote', methods=['POST'])
def vote_review(review_id):
    data = request.json
    action = data.get('action')

    if action not in ['like', 'dislike']:
        return jsonify({"error": "Invalid action"}), 400

    # 明确指定要增加的字段
    update_field = "likes" if action == "like" else "dislikes"
    
    # 先更新文档
    result = reviews_col.update_one(
        {"_id": ObjectId(review_id)},
        {"$inc": {update_field: 1}}
    )
    
    if result.modified_count:
        # 获取更新后的文档
        updated_review = reviews_col.find_one({"_id": ObjectId(review_id)})
        return jsonify({
            "likes": updated_review.get("likes", 0),
            "dislikes": updated_review.get("dislikes", 0)
        })
    else:
        return jsonify({"error": "Review not found"}), 404

## GET MOVIE REVIEWS
@app.route('/movies/<int:tmdb_id>/reviews', methods=['GET'])
def get_reviews_for_movie(tmdb_id):
    reviews_list = list(reviews_col.find({"tmdb_id": tmdb_id}))
    for r in reviews_list:
        r["_id"] = str(r["_id"])
        r["sentiment"] = r.get("sentiment", "LABEL_2")  # Default to neutral if missing
    return jsonify(reviews_list)

# USER PAGE
## GET USER

@app.route('/userpage')
def userpage():
    if 'logged_in' not in session or not session['logged_in']:
        return redirect(url_for('login'))

    user = users_col.find_one({"username": session['username']})
    if not user:
        return render_template("404.html", message="User not found"), 404

    user['_id'] = str(user['_id'])

    user_reviews = []
    for r in reviews_col.find({"user_id": user['_id']}):
        tmdb_id = r.get("tmdb_id")
        movie_title = get_movie_title_by_id(tmdb_id) if tmdb_id else "Unknown Title"
        release_date = r.get("release_date", "")
        created = r.get("created_at")

        review = {
            "_id": str(r["_id"]),
            "tmdb_id": tmdb_id,  
            "movie_title": movie_title,
            "review_title": r.get("review_title", ""),
            "review_text": r.get("review_text", ""),
            "release_date": release_date.strftime('%Y') if isinstance(release_date, datetime) else str(release_date)[:4] if release_date else "Unknown",
            "user_rating": r.get("user_rating", 0),
            "created_at": created.strftime("%Y-%m-%d") if created else "Unknown"
        }
        user_reviews.append(review)

    user_watchlists = list(watchlists_col.find({"username": user['username']}))

    username = session.get('username', 'Sign up/Login')

    return render_template('userpage.html', user=user, watchlists=user_watchlists, reviews=user_reviews, username=username )


## UPDATE OR EDIT REVIEW
@app.route('/reviews/<review_id>/edit', methods=['PUT'])
def update_review(review_id):
    data = request.json
    reviews_col.update_one(
        {"_id": ObjectId(review_id)},
        {"$set": {
            "user_rating": float(data.get("user_rating")),
            "review_text": data.get("review_text")
        }}
    )
    return jsonify({"message": "Review updated"}), 200

## DELETE REVIEW
@app.route('/reviews/<review_id>/delete', methods=['POST'])
def delete_review(review_id):
    result = reviews_col.delete_one({"_id": ObjectId(review_id)})
    if result.deleted_count:
        return jsonify({"message": "Review deleted"}), 200
    return jsonify({"error": "Review not found"}), 404

## REMOVE WATCHLIST MOVIEE
@app.route('/watchlists/<watchlist_id>/remove', methods=['POST'])
def remove_from_watchlist(watchlist_id):
    result = watchlists_col.delete_one({"_id": ObjectId(watchlist_id)})
    if result.deleted_count:
        return jsonify({"message": "Watchlist movie removed"}), 200
    return jsonify({"error": "Watchlist movie not found"}), 404

## UPDATE USER BIO
@app.route('/users/<user_id>', methods=['PUT'])
def update_user(user_id):
    data = request.json
    update_result = users_col.update_one(
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

    users_col.delete_one({'username': username})

    reviews_col.delete_many({'username': username})
    watchlists_col.delete_many({'username': username})

    session.clear()

    flash("Your account has been successfully deleted.", "success")

    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)
