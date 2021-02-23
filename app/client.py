import os
import json
import requests
from kafka import KafkaConsumer, KafkaProducer
from kafka.oauth import AbstractTokenProvider
from stix2validator import validate_file, print_results,validate_string,validate_instance
from stix2validator import ValidationOptions

path_to_kafka_cert = os.path.join(os.path.abspath(os.getcwd()),'app' ,'auth_files', 'for_clients.crt')


OAUTH_CLIENT_ID = os.environ.get('OAUTH_CLIENT_ID', default = 'SIEM')
BOOTSTRAP_SERVERS = os.environ.get('BOOTSTRAP_SERVERS', default = 'bootstrap.146.124.106.170.nip.io:443')
OAUTH_TOKEN_ENDPOINT_URI = os.environ.get('OAUTH_TOKEN_ENDPOINT_URI',default = 'http://sphinx-kubernetes.intracom-telecom.com/SMPlatform/manager/rst/getKafkaToken')
KAFKA_USERNAME = os.environ.get('KAFKA_USERNAME', default = 'kafkauser')
KAFKA_PASSWORD = os.environ.get('KAFKA_PASSWORD', default = 'kafkauser123')
SM_IP = os.environ.get('SM_IP', default = 'http://sphinx-kubernetes.intracom-telecom.com/SMPlatform/manager/rst')
KAFKA_CERT = os.environ.get('KAFKA_CERT', default = path_to_kafka_cert)

class TokenProvider(AbstractTokenProvider):

    def __init__(self):
        self.kafka_ticket = json.loads(requests.post(f'{SM_IP}/KafkaAuthentication',data={'username': KAFKA_USERNAME,'password': KAFKA_PASSWORD}).text)['data']

    def token(self):
        kafka_token = json.loads(requests.get(OAUTH_TOKEN_ENDPOINT_URI, auth=(OAUTH_CLIENT_ID, self.kafka_ticket)).text)['access_token']
        return kafka_token

USER    = os.environ.get('USER', default = 'users_usernameN')
PASSWORD    = os.environ.get('PASSWORD',default = 'users_passwordnameN')
RCRA_ADDRESS = os.environ.get('RCRA_ADDRESS', default = '127.0.0.1:5002')

#risk-assessment:5002/save_report

def token():
    return requests.get(f'{SM_IP}/Authentication?username={USER}&password={PASSWORD}').json()['data']


def rcra_1_a(ticket):
	#response = requests.get(f'{RCRA_ADDRESS}/save_report', headers={'Authorization': f'Bearer {ticket}'})
	response = requests.get(f'{RCRA_ADDRESS}/save_report')
	# The request was successful
	if (response.status_code == 200):
		print(True)
	else:
		print(response.status_code)

	data = response.json()
	results = validate_instance(data)
	print_results(results)
	print(results.is_valid)

def rcra_1():
	print('rcra 1 kafka')
	#prerequ
	ticket = token()
	print('a')
	rcra_1_a(ticket)

rcra_1()

consumer = KafkaConsumer(bootstrap_servers=BOOTSTRAP_SERVERS,auto_offset_reset='earliest', security_protocol='SASL_SSL', sasl_mechanism='OAUTHBEARER', sasl_oauth_token_provider=TokenProvider(), ssl_cafile=KAFKA_CERT)
consumer.subscribe(['rcra-report-topic'])
print('reading')
for msg in consumer:
    data = json.loads(msg.value.decode())
    print(data)
    results = validate_instance(data)
    print(results.is_valid)
    break