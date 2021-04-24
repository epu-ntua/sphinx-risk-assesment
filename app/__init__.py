from flask import Flask
from flask_restful import Api

from config import Config
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from app.api import *
from flask_bootstrap import Bootstrap
import threading, time

app = Flask(__name__)
Bootstrap(app)

app.config.from_object(Config)
# api = Api(app)

db = SQLAlchemy(app)
migrate = Migrate(app, db)


from app import routes
from app import models

from app import errors

from app import producer

thread1 = threading.Thread(target=producer.get_kafka_data_print_test("rcra-report-topic"))
thread2 = threading.Thread(target=producer.get_kafka_data_print_test("dtm-alert"))

thread1.start()
thread2.start()

# from app import api
#
# api.add_resource(RCRAgetFCDEversion, '/RCRAgetFCDEversion')
# api.add_resource(RCRAgetversion, '/RCRAgetversion')