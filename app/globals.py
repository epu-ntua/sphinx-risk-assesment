import os

GLOBAL_SERVER_PORT = os.environ.get('GLOBAL_SERVER_PORT') if os.environ.get('GLOBAL_SERVER_PORT') else "5002"
GLOBAL_SERVER_ADDRESS = os.environ.get('GLOBAL_SERVER_ADDRESS') if os.environ.get('GLOBAL_SERVER_ADDRESS') else "127.0.0.1"

GLOBAL_IP = os.environ.get('GLOBAL_IP') if os.environ.get('GLOBAL_IP') else "http://127.0.0.1:5002/"

serverPort = GLOBAL_SERVER_PORT
serverAddress = GLOBAL_SERVER_ADDRESS
# serverAddress = '0.0.0.0'
