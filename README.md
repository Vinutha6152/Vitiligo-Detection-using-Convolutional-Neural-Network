# Vitiligo Detection using CNN

A web application that uses a Convolutional Neural Network (CNN) to classify an uploaded skin image as Vitiligo, Healthy Skin, or Not a Skin Image.

> This is a learning project. It is not a medical diagnosis tool.

## Features
- User signup and login with hashed passwords
- Image upload and prediction with a confidence score
- Flask web interface connected to a trained TensorFlow/Keras model

## Tech stack
Python, TensorFlow, Keras, Flask, SQLite, HTML, CSS

## Project structure
- `app.py`: Flask application and prediction logic
- `vitiligo_model.h5`: trained CNN model
- `vitiligo_model_training.ipynb`: model training notebook
- `templates/`: HTML pages

## Run locally
1. Install Python 3.10 or 3.11.
2. Install dependencies: `pip install -r requirements.txt`
3. Start the app: `python app.py`
4. Open http://127.0.0.1:5000/ in your browser.

## Research
Published as "Vitiligo Detection Using CNN" in a peer-reviewed international research journal, December 2024.
