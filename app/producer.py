from pykafka import KafkaClient, SslConfig
import json
from datetime import datetime
import uuid
import time

def get_kafka_client():
    return KafkaClient(hosts='127.0.0.1:9092')
    # We are going to use something like this
    # config = SslConfig(cafile='/your/ca.cert',
    #                     certfile='/your/client.cert',  # optional
    #                     keyfile='/your/client.key',  # optional
    #                     password='unlock my client key please')  # optional
    # client = KafkaClient(hosts="127.0.0.1:<ssl-port>,...",
    #                       ssl_config=config)



#KAFKA PRODUCER
client = get_kafka_client()
# client = KafkaClient(hosts="localhost:9092")
topic = client.topics['RCRAsample']
producer = topic.get_sync_producer()

# CONSTRUCT MESSAGE AND SEND IT TO KAFKA
data = {}
data['testline'] = '00001'
# GENERATE UUID
def generate_uuid():
    return uuid.uuid4()

def generate_checkpoint(steps):
    i = 0
    while i < steps:
        data['key'] = data['testline'] + '_' + str(generate_uuid())
        data['timestamp'] = str(datetime.utcnow())
        message = json.dumps(data)
        # yield message
        producer.produce(message.encode('ascii'))
        time.sleep(1)
        i=i+1

