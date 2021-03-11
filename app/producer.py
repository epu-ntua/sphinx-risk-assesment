import requests
from kafka import KafkaProducer
from datetime import datetime
from time import sleep
from json import dumps
import configparser
import uuid

#check this too : https://pypi.org/project/javaproperties/


class KafkaInitialiser:
    def __init__(self):
        url = "http://sphinx-kubernetes.intracom-telecom.com:8080/SMPlatform/manager/rst/KafkaAuthentication"
        payload = {
            'username': 'testR1',
            'password': 'testR1123!@'
        }
        response = requests.request("POST", url, data=payload)
        selectedticket = response.json()
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
