from app import app
from flask import render_template

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.route('/test_gd')
def test_gd():
    return render_template('test_gd.html')