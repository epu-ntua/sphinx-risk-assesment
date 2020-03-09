from flask import Flask
from app import db
from app import app
# app = Flask(__name__)


#Function to auto import in new python shell
#flask shell
@app.shell_context_processor
def make_shell_context():
    return {'db': db}
