from flask import render_template, request, redirect, jsonify, Response, flash
from multiprocessing import Process
from app.producer import *
from app.globals import *
from app.utils import *
from app.forms import *
from app import app
import ast
from app.utils.utils_database import *


@app.context_processor
def serverInfo():
    return dict(serverAddress=serverAddress, serverPort=serverPort)


@app.before_first_request
def active_kafka_listeners():
    print("---- Before First Run ----", flush=True)
    # get_kafka_data_print_test("rcra-report-topic")
    t1 = Process(target=get_kafka_data_print_test, args=("rcra-report-topic",))
    # t2 = Process(target=get_kafka_data_print_test, args=("dtm-alert",))
    t1.start()
    # t2.start()


@app.route('/')
@app.route('/home/')
def entry_page():
    return render_template('templates_supporting/entry_page.html')


@app.route('/setup-database/', methods=['GET'])
def setup_database():
    rcra_db_init()
    return Response(status=200)

@app.errorhandler(404)
def not_found_error(error):
    return render_template('templates_supporting/404.html', port=serverPort), 404


@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('templates_supporting/500.html', port=serverPort), 500
