from flask import render_template
from app import app, db
from app.globals import *


@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html', port=serverPort), 404


@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('500.html', port=serverPort), 500
