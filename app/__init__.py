from flask import Flask
from flask_restful import Api

from config import Config
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from app.api import *
from flask_bootstrap import Bootstrap
#from multiprocessing import Process

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

#t1 = Process(target=producer.get_kafka_data_print_test, args=("rcra-report-topic",))
#t2 = Process(target=producer.get_kafka_data_print_test, args=("dtm-alert",))

#t1.start()
#t2.start()

# from app import api
#
# api.add_resource(RCRAgetFCDEversion, '/RCRAgetFCDEversion')
# api.add_resource(RCRAgetversion, '/RCRAgetversion')
