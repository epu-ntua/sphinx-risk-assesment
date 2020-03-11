from app import app
from flask import render_template

@app.route('/')
@app.route('/home')
def entry_page():
    return render_template('entry_page.html')

@app.route('/dashboardCorrelate')
def dashboardAssetThreat():
    return render_template('dashboardCorrelate.html')

@app.route('/test_gd')
def test_gd():
    return render_template('test_gd.html')