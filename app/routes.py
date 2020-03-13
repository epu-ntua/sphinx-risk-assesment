from app import app
from flask import render_template

@app.route('/')
@app.route('/home')
def entry_page():
    return render_template('entry_page.html')

@app.route('/assets')
def assets():
    return render_template('assets.html')

@app.route('/assets/1/vulnerabilities')
def vulnerabilities():
    return render_template('vulnerabilities.html')

@app.route('/assets/1/vulnerabilities/1/threats')
def threats():
    return render_template('threats.html')

@app.route('/test_gd')
def test_gd():
    return render_template('test_gd.html')