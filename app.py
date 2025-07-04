import os
import re
import sqlite3
import numpy as np
from flask import Flask, render_template, request, redirect, url_for, flash, session
from tensorflow.keras.models import load_model
from tensorflow.keras.preprocessing.image import load_img, img_to_array
from werkzeug.security import generate_password_hash, check_password_hash
from PIL import Image

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'

# Load the trained model
model_path = os.path.abspath('vitiligo_model.h5')
model = load_model(model_path)

# Configure upload folder
UPLOAD_FOLDER = 'static/uploads/'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def preprocess_image(filepath):
    img = load_img(filepath, target_size=(150, 150))
    img_array = img_to_array(img)
    img_array = img_array / 255.0
    img_array = np.expand_dims(img_array, axis=0)
    return img_array

def predict_image(filepath):
    img_array = preprocess_image(filepath)
    prediction = model.predict(img_array)

    # Ensure this list matches the exact class index order used in training
    class_names = ['Healthy Skin', 'Not a Skin Image','Vitiligo']  # Change if needed
    predicted_index = int(np.argmax(prediction[0]))
    predicted_class = class_names[predicted_index]
    confidence = float(prediction[0][predicted_index]) * 100

    print(f"[DEBUG] Probabilities: {prediction[0]}")
    print(f"[DEBUG] Predicted class: {predicted_class} ({confidence:.2f}%)")

    return predicted_class, confidence


def init_db():
    connection = sqlite3.connect('users.db')
    cursor = connection.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        first_name TEXT NOT NULL,
                        last_name TEXT NOT NULL,
                        email TEXT NOT NULL UNIQUE,
                        password TEXT NOT NULL,
                        gender TEXT NOT NULL,
                        dob TEXT NOT NULL,
                        age INTEGER NOT NULL
                    )''')
    connection.commit()
    connection.close()

init_db()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        gender = request.form['gender']
        dob = request.form['dob']
        age = int(request.form['age'])

        if not re.match(r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,12}$', password):
            flash('Password must be 8-12 characters, include 1 uppercase, 1 lowercase, 1 number, and 1 special character.', 'error')
            return redirect(url_for('signup'))

        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return redirect(url_for('signup'))

        hashed_password = generate_password_hash(password)

        connection = sqlite3.connect('users.db')
        cursor = connection.cursor()
        try:
            cursor.execute('''INSERT INTO users (first_name, last_name, email, password, gender, dob, age)
                               VALUES (?, ?, ?, ?, ?, ?, ?)''',
                           (first_name, last_name, email, hashed_password, gender, dob, age))
            connection.commit()
            flash('Signup successful. Please login.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Email already exists.', 'error')
        finally:
            connection.close()

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        connection = sqlite3.connect('users.db')
        cursor = connection.cursor()
        cursor.execute('SELECT * FROM users WHERE email=?', (email,))
        user = cursor.fetchone()
        connection.close()

        if user and check_password_hash(user[4], password):
            session['user'] = user[3]
            flash('Login successful.', 'success')
            return redirect(url_for('upload'))
        else:
            flash('Invalid credentials or account does not exist. Sign up first.', 'error')
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user', None)
    flash('Logged out successfully.', 'success')
    return redirect(url_for('index'))

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if 'user' not in session:
        flash('Please log in first.', 'error')
        return redirect(url_for('login'))

    if request.method == 'POST':
        if 'image' not in request.files:
            flash('No image selected.', 'error')
            return redirect(url_for('upload'))
        file = request.files['image']
        if file.filename == '':
            flash('Please select a file.', 'error')
            return redirect(url_for('upload'))
        if not allowed_file(file.filename):
            flash('Only image files (png, jpg, jpeg, gif) are allowed.', 'error')
            return redirect(url_for('upload'))

        filepath = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(filepath)
        prediction, confidence = predict_image(filepath)
        flash(f'Prediction: {prediction} ({confidence:.2f}% confidence)', 'success')
        return render_template('result.html', prediction=prediction, confidence=confidence, filepath=filepath)

    return render_template('upload.html')

if __name__ == '__main__':
    app.run(debug=True)
