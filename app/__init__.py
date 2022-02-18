from flask import Flask
from flask_restful import Api

from config import Config
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_bootstrap import Bootstrap
#from multiprocessing import Process

app = Flask(__name__)
Bootstrap(app)

app.config.from_object(Config)
# api = Api(app)

db = SQLAlchemy(app)
migrate = Migrate(app, db)

from app.routes import routes_supporting, routes_asset_repo, routes_dashboard,\
    routes_testing, routes_risk_assessment
from app import models


from app import producer
# from app import utils
from app.utils import stix2_custom, utils_communication, utils_database,\
    utils_risk_assessment, utils_3rd_party_data_handling

db.create_all()
db.session.commit()

utils_database.rcra_db_init()
#t1 = Process(target=producer.get_kafka_data_print_test, args=("rcra-report-topic",))
#t2 = Process(target=producer.get_kafka_data_print_test, args=("dtm-alert",))

#t1.start()
#t2.start()

