from flask import Flask
from flask_restful import Api

from config import Config
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from app.api import *
app = Flask(__name__)
app.config.from_object(Config)
# api = Api(app)

db = SQLAlchemy(app)
migrate = Migrate(app, db)


from app import routes
from app import models
from app import errors
# from app import api
#
# api.add_resource(RCRAgetFCDEversion, '/RCRAgetFCDEversion')
# api.add_resource(RCRAgetversion, '/RCRAgetversion')