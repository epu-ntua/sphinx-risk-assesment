import requests
import os
import requests
import json
from kafka import KafkaProducer
from kafka.oauth import AbstractTokenProvider

from datetime import datetime
from time import sleep
from json import dumps
import configparser
import uuid

#check this too : https://pypi.org/project/javaproperties/
os.environ["SM_IP"] = "http://sphinx-kubernetes.intracom-telecom.com:8080/SMPlatform/manager/rst/KafkaAuthentication"
os.environ["KAFKA_USERNAME"] = "testR1"
os.environ["KAFKA_PASSWORD"] = "testR1123!@"
os.environ["OAUTH_CLIENT_ID"] = ""
os.environ["OAUTH_TOKEN_ENDPOINT_URI"] = ""
os.environ["BOOTSTRAP_SERVERS"] = "kafka-1:19092"
os.environ["KAFKA_CERT"] = "1"


SM_IP                    = os.environ.get('SM_IP')
KAFKA_USERNAME           = os.environ.get('KAFKA_USERNAME')
KAFKA_PASSWORD           = os.environ.get('KAFKA_PASSWORD')
OAUTH_CLIENT_ID          = os.environ.get('OAUTH_CLIENT_ID')
OAUTH_TOKEN_ENDPOINT_URI = os.environ.get('OAUTH_TOKEN_ENDPOINT_URI')
BOOTSTRAP_SERVERS        = os.environ.get('BOOTSTRAP_SERVERS')
KAFKA_CERT               = os.environ.get('KAFKA_CERT')#FULL PATH OF THE CERTIFICATE LOCATION



class TokenProvider(AbstractTokenProvider):

    def __init__(self):
        self.kafka_ticket = json.loads(requests.post(f'{SM_IP}/KafkaAuthentication',data={'username': KAFKA_USERNAME,'password': KAFKA_PASSWORD}).text)['data']

    def token(self):
        kafka_token = json.loads(requests.get(OAUTH_TOKEN_ENDPOINT_URI, auth=(OAUTH_CLIENT_ID, self.kafka_ticket)).text)['access_token']

        return kafka_token

#KAFKA CLIENT PRODUCER
producer = KafkaProducer(bootstrap_servers=BOOTSTRAP_SERVERS,
                        security_protocol='SASL_SSL',
                        sasl_mechanism='OAUTHBEARER',
                        sasl_oauth_token_provider=TokenProvider(),
                        ssl_cafile=KAFKA_CERT,
                        value_serializer=lambda value: value.encode())


producer.send('python-topic', json.dumps({'data': {'some_key': 'some_value'}}))

producer.flush()
#
# #KAFKA CLIENT CONSUMER
#
# consumer = KafkaConsumer(bootstrap_servers=BOOTSTRAP_SERVERS,
#                         security_protocol='SASL_SSL',
#                         sasl_mechanism='OAUTHBEARER',
#                         sasl_oauth_token_provider=TokenProvider(),
#                         ssl_cafile=KAFKA_CERT)
#
# consumer.subscribe(['python-topic'])
#
# for msg in consumer:
#     print(json.loads(msg.value.decode()))
#

class KafkaInitialiser:
    def __init__(self):
        url = "http://sphinx-kubernetes.intracom-telecom.com:8080/SMPlatform/manager/rst/KafkaAuthentication"
        payload = {
            'username': 'testR1',
            'password': 'testR1123!@'
        }
        response = requests.request("POST", url, data=payload)

        selectedticket = response.json()
        print(selectedticket)
        KAFKA_TICKET = selectedticket["data"]

        servers = "localhost:9092,kafka-1:19092,kafka-2:29092,kafka-3:39092"
        TRUSTSTORE_PATH = "test-certs/kafka.client.truststore.jks"
        TRUSTSTORE_PASSWORD = "123"

        config = configparser.ConfigParser()
        config['DEFAULT'] = {'bootstrap.servers': servers,
                             'group.id': 'KafkaExampleProducer',
                             'security.protocol': 'SASL_SSL',
                             'sasl.mechanism': 'OAUTHBEARER',
                             'sasl.jaas.config': 'org.apache.kafka.common.security.oauthbearer.OAuthBearerLoginModule required ;',
                             'sasl.login.callback.handler.class': 'io.strimzi.kafka.oauth.client.JaasClientOauthLoginCallbackHandler',
                             'auto.offset.reset': 'earliest',
                             'enable.auto.commit': True,
                             'ssl.truststore.location': TRUSTSTORE_PATH,
                             'ssl.truststore.password': TRUSTSTORE_PASSWORD,
                             'ssl.trustStore.Type': 'PKCS12',
                             'oauth.client.secret': KAFKA_TICKET,
                             'value.serializer': lambda x: dumps(x).encode('utf-8')}

        # ("ssl.keystore.location", "test-certs/kafka.client.keystore.jks")
        # ("ssl.keystore.password", "asdfasdf")
        # ("ssl.key.password", "asdf")
        # producer = KafkaProducer(bootstrap_servers=['localhost:9092'],
        #                          value_serializer=lambda x:dumps(x).encode('utf-8'))

        producer = KafkaProducer(config)

        data = {}


# def kafka_connect(steps):
#     url = "http://sphinx-kubernetes.intracom-telecom.com:8080/SMPlatform/manager/rst/KafkaAuthentication"
#     payload = {
#         'username': 'testR1',
#         'password': 'testR1123!@'
#         }
#     response = requests.request("POST", url, data=payload)
#     selectedticket = response.json()
#     KAFKA_TICKET = selectedticket["data"]
#
#     servers = "localhost:9092,kafka-1:19092,kafka-2:29092,kafka-3:39092"
#     TRUSTSTORE_PATH = "test-certs/kafka.client.truststore.jks"
#     TRUSTSTORE_PASSWORD ="123"
#
#     config = configparser.ConfigParser()
#     config['DEFAULT'] = {'bootstrap.servers': servers,
#                          'group.id': 'KafkaExampleProducer',
#                          'security.protocol': 'SASL_SSL',
#                          'sasl.mechanism':'OAUTHBEARER',
#                          'sasl.jaas.config':'org.apache.kafka.common.security.oauthbearer.OAuthBearerLoginModule required ;',
#                          'sasl.login.callback.handler.class':'io.strimzi.kafka.oauth.client.JaasClientOauthLoginCallbackHandler',
#                          'auto.offset.reset':'earliest',
#                          'enable.auto.commit':True,
#                          'ssl.truststore.location':TRUSTSTORE_PATH,
#                          'ssl.truststore.password':TRUSTSTORE_PASSWORD,
#                          'ssl.trustStore.Type':'PKCS12',
#                          'oauth.client.secret':KAFKA_TICKET,
#                          'value.serializer':lambda x:dumps(x).encode('utf-8')}
#
#     # ("ssl.keystore.location", "test-certs/kafka.client.keystore.jks")
#     # ("ssl.keystore.password", "asdfasdf")
#     # ("ssl.key.password", "asdf")
#     # producer = KafkaProducer(bootstrap_servers=['localhost:9092'],
#     #                          value_serializer=lambda x:dumps(x).encode('utf-8'))
#
#     producer = KafkaProducer(config)
#
#     data = {}
#
#
#     for e in range(steps):
#         data['number'] = str(e)
#         data['key'] = str(generate_uuid())
#         data['timestamp'] = str(datetime.utcnow())
#         producer.send('RCRAsample', value=data)
#         # # flush the message buffer to force message delivery to broker on each iteration
#         # producer.flush()
#         sleep(5)

# GENERATE UUID
def generate_uuid():
    return uuid.uuid4()

# def generate_checkpoint(steps):
#     i = 0
#     while i < steps:
#         data['key'] = data['testline'] + '_' + str(generate_uuid())
#         data['timestamp'] = str(datetime.utcnow())
#         message = json.dumps(data)
#         # yield message
#         producer.produce(message.encode('ascii'))
#         time.sleep(1)
#         i=i+1


def generate_checkpoint(steps , kafkaInitialiser):
    for e in range(steps):
        kafkaInitialiser.data['number'] = str(e)
        kafkaInitialiser.data['key'] = str(generate_uuid())
        kafkaInitialiser.data['timestamp'] = str(datetime.utcnow())
        kafkaInitialiser.producer.send('RCRAsample', value=kafkaInitialiser.data)
        # # flush the message buffer to force message delivery to broker on each iteration
        # producer.flush()
        sleep(5)
