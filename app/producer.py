import requests
import os
import requests
import json
import sys
from kafka import KafkaProducer, KafkaConsumer
from kafka.oauth import AbstractTokenProvider
from kafka.errors import KafkaError

from app import app

from datetime import datetime
from time import sleep
from json import dumps
import configparser
import uuid
import threading, time

# check this too : https://pypi.org/project/javaproperties/
# 8080
path_to_kafka_cert = os.path.join(os.path.abspath(os.getcwd()), 'app', 'auth_files', 'for_clients.crt')
# path_to_kafka_cert = sys.path[0] + "\""
# os.environ["SM_IP"] = "http://sphinx-kubernetes.intracom-telecom.com/SMPlatform/manager/rst"
# os.environ["KAFKA_USERNAME"] = "kafkauser"
# os.environ["KAFKA_PASSWORD"] = "kafkauser123"
# os.environ["OAUTH_CLIENT_ID"] = "SIEM"
# os.environ["OAUTH_TOKEN_ENDPOINT_URI"] = "http://sphinx-kubernetes.intracom-telecom.com/SMPlatform/manager/rst/getKafkaToken"
# os.environ["BOOTSTRAP_SERVERS"] = "bootstrap.146.124.106.170.nip.io:443"
os.environ["KAFKA_CERT"] = path_to_kafka_cert

SM_IP = os.environ.get('SM_IP') if os.environ.get(
    'SM_IP') else "http://sphinx-kubernetes.intracom-telecom.com/SMPlatform/manager/rst"
KAFKA_USERNAME = os.environ.get('KAFKA_USERNAME') if os.environ.get('KAFKA_USERNAME') else "kafkauser"
KAFKA_PASSWORD = os.environ.get('KAFKA_PASSWORD') if os.environ.get('KAFKA_PASSWORD') else "kafkauser123"
OAUTH_CLIENT_ID = os.environ.get('OAUTH_CLIENT_ID') if os.environ.get('OAUTH_CLIENT_ID') else "SIEM"
OAUTH_TOKEN_ENDPOINT_URI = os.environ.get('OAUTH_TOKEN_ENDPOINT_URI') if os.environ.get(
    'OAUTH_TOKEN_ENDPOINT_URI') else "http://sphinx-kubernetes.intracom-telecom.com/SMPlatform/manager/rst/getKafkaToken"
BOOTSTRAP_SERVERS = os.environ.get('BOOTSTRAP_SERVERS') if os.environ.get(
    'BOOTSTRAP_SERVERS') else "bootstrap.146.124.106.170.nip.io:443"
KAFKA_CERT = os.environ.get('KAFKA_CERT')  # FULL PATH OF THE CERTIFICATE LOCATION


# print(SM_IP)

class TokenProvider(AbstractTokenProvider):

    def __init__(self):
        self.kafka_ticket = json.loads(requests.post(SM_IP + '/KafkaAuthentication', data={'username': KAFKA_USERNAME,
                                                                                           'password': KAFKA_PASSWORD}).text)[
            'data']

    def token(self):
        kafka_token = \
        json.loads(requests.get(OAUTH_TOKEN_ENDPOINT_URI, auth=(OAUTH_CLIENT_ID, self.kafka_ticket)).text)[
            'access_token']

        return kafka_token


# class MykafkaProducer:
#     def __init__(self):
#         try:
#             self.producer = KafkaProducer(bootstrap_servers=BOOTSTRAP_SERVERS,
#                             security_protocol='SASL_SSL',
#                             sasl_mechanism='OAUTHBEARER',
#                             sasl_oauth_token_provider=TokenProvider(),
#                             ssl_cafile= path_to_kafka_cert,
#                             value_serializer=lambda value: value.encode())
#         except Exception as e:
#             print(f'ERROR initializing Kafka Producer: {e.__str__()}')
#
#     def get_producer(self):
#         return self.producer
#
#     def send_topic(self, _producer: KafkaProducer = None, _topic='vaaas_report', _data=None):
#         prod = _producer if _producer else self.producer
#         dat = _data if _data else {'data': {'some_key': 'some_value'}}
#         try:
#             prod.send(_topic, dat)
#             prod.flush()
#         except Exception as e:
#             print(f'ERROR on sending message to kafka topic: {e.__str__()}')

print("-----------Env Variables Start-----------------")
print(SM_IP)
print(KAFKA_USERNAME)
print(KAFKA_PASSWORD)
print(OAUTH_CLIENT_ID)
print(OAUTH_TOKEN_ENDPOINT_URI)
print(BOOTSTRAP_SERVERS)
print(BOOTSTRAP_SERVERS)
print(KAFKA_CERT)
print("-----------Env Variables End-----------------", flush=True)

# try:
# producer = KafkaProducer(bootstrap_servers=BOOTSTRAP_SERVERS,
#                          security_protocol='SASL_SSL',
#                          sasl_mechanism='OAUTHBEARER',
#                          sasl_oauth_token_provider=TokenProvider(),
#                          ssl_cafile=path_to_kafka_cert,
#                          value_serializer=lambda value: value.encode(),
#                          api_version=(2, 5, 0))


# except KafkaError:
#    print("Kafka producer initialisation encountered an error")

def SendKafkaReport(report):
    # return ;
    # KAFKA CLIENT PRODUCER
    producer = KafkaProducer(bootstrap_servers=BOOTSTRAP_SERVERS,
                             security_protocol='SASL_SSL',
                             sasl_mechanism='OAUTHBEARER',
                             sasl_oauth_token_provider=TokenProvider(),
                             ssl_cafile=path_to_kafka_cert,
                             value_serializer=lambda value: value.encode(),
                             api_version=(2, 5, 0))
    # print(BOOTSTRAP_SERVERS)
    # print(os.environ.get('BOOTSTRAP_SERVERS'))
    # # producer = KafkaProducer(bootstrap_servers=BOOTSTRAP_SERVERS,
    # #                         security_protocol='SASL_SSL',
    # #                         sasl_mechanism='OAUTHBEARER',
    # #                         sasl_oauth_token_provider=TokenProvider(),
    # #                         ssl_cafile= path_to_kafka_cert,
    # #                         value_serializer=lambda value: value.encode())
    #
    #
    try:
        producer.send('rcra-report-topic', json.dumps(report))
    except KafkaError:
        print("Kafka producing sending data encountered an error")

    result = producer.flush()
    print(result, flush=True)
    producer.close()


# GENERATE UUID
def generate_uuid():
    return uuid.uuid4()


# def generate_checkpoint(steps):++
#     i = 0
#     while i < steps:
#         data['key'] = data['testline'] + '_' + str(generate_uuid())
#         data['timestamp'] = str(datetime.utcnow())
#         message = json.dumps(data)
#         # yield message
#         producer.produce(message.encode('ascii'))
#         time.sleep(1)
#         i=i+1


def generate_checkpoint(steps, kafkaInitialiser):
    for e in range(steps):
        kafkaInitialiser.data['number'] = str(e)
        kafkaInitialiser.data['key'] = str(generate_uuid())
        kafkaInitialiser.data['timestamp'] = str(datetime.utcnow())
        kafkaInitialiser.producer.send('RCRAsample', value=kafkaInitialiser.data)
        # # flush the message buffer to force message delivery to broker on each iteration
        # producer.flush()
        sleep(5)


def get_kafka_data(kafka_topic):
    # #KAFKA CLIENT CONSUMER
    #   try:
    print("Trying Consume")
    consumer = KafkaConsumer(bootstrap_servers=BOOTSTRAP_SERVERS,
                             auto_offset_reset='earliest',
                             security_protocol='SASL_SSL',
                             sasl_mechanism='OAUTHBEARER',
                             sasl_oauth_token_provider=TokenProvider(),
                             ssl_cafile=path_to_kafka_cert,
                             api_version=(2, 5, 0)
                             )
    # 'python-topic' default kafka topic
    consumer.subscribe([kafka_topic])
    # except KafkaError:
    #   print("KafkaConsumer error when initialising")
    #  return "Encountered Error"

    for msg in consumer:
        if msg:
            dat = {
                "msg" : msg
                #'msg_value': msg.value(),  # This is the actual content of the message
                #'msg_headers': msg.headers(),  # Headers of the message
                #'msg_key': msg.key(),  # Message Key
                #'msg_partition': msg.partition(),  # Partition id from which the message was extracted
                #'msg_topic': msg.topic(),  # Topic in which Producer posted the message to
            }
            print(dat)
            # print("Kafka output:", json.loads(msg.value.decode()))

    consumer.close()

def get_kafka_data_print_test(kafka_topic):
    # #KAFKA CLIENT CONSUMER
    #   try:
    print("Trying Consume")
    consumer = KafkaConsumer(bootstrap_servers=BOOTSTRAP_SERVERS,
                             # auto_offset_reset='earliest',
                             security_protocol='SASL_SSL',
                             sasl_mechanism='OAUTHBEARER',
                             sasl_oauth_token_provider=TokenProvider(),
                             ssl_cafile=path_to_kafka_cert,
                             api_version=(2, 5, 0)
                             )
    # 'python-topic' default kafka topic
    consumer.subscribe([kafka_topic])
    # except KafkaError:
    #   print("KafkaConsumer error when initialising")
    #  return "Encountered Error"

    for msg in consumer:
        if msg:
            dat = {
                "msg" : msg
                #'msg_value': msg.value(),  # This is the actual content of the message
                #'msg_headers': msg.headers(),  # Headers of the message
                #'msg_key': msg.key(),  # Message Key
                #'msg_partition': msg.partition(),  # Partition id from which the message was extracted
                #'msg_topic': msg.topic(),  # Topic in which Producer posted the message to
            }
            # print(dat)
            # print("Kafka output:", json.loads(msg.value.decode()))

    if kafka_topic == "rcra-report-topic":
        print("--------------Kafka Received: rcra-report-topic -------------------------")
        print(dat)
        print("-------------------------------------------------------------------------")
    elif kafka_topic == "dtm-alert":
        print("--------------Kafka Received: dtm-alert -------------------------")
        print(dat)
        print("-------------------------------------------------------------------------")
    else:
        print("--------------Kafka Received: other topic -------------------------")
        print(dat)
        print("-------------------------------------------------------------------------")
    # consumer.close()

# get_kafka_data_print_test("rcra-report-topic")
