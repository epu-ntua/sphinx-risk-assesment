from kafka import KafkaProducer
import json
from datetime import datetime
from time import sleep
from json import dumps

import uuid
import time

producer = KafkaProducer(bootstrap_servers=['localhost:9092'],
                         value_serializer=lambda x:
                         dumps(x).encode('utf-8'))

data = {}
# data['testline'] = '00001'
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
def generate_checkpoint(steps):
    for e in range(steps):
        data['number'] = str(e)
        data['key'] = str(generate_uuid())
        data['timestamp'] = str(datetime.utcnow())
        producer.send('RCRAsample', value=data)
        # # flush the message buffer to force message delivery to broker on each iteration
        # producer.flush()
        sleep(5)