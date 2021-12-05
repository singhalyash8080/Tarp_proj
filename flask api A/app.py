# imports required for ascon algo 
from flask import Flask, jsonify, request

#imports required for twine algo
from xtwine import Twine

#imports required for the ascon algo
import ascon

#import required for exchanging keys
import exchangeKeys

#importing the required libraries   
from flask import Flask
from flask_pymongo import PyMongo
from bson.objectid import ObjectId
from flask_cors import CORS, cross_origin


# creating a Flask app
app = Flask(__name__)
cors = CORS(app)
app.config['CORS_HEADERS'] = 'Content-Type'

mongodb_client = PyMongo(app, uri = "mongodb+srv://yashyash:yashyash2@cluster0.sarnf.mongodb.net/myFirstDatabase?retryWrites=true&w=majority")
db = mongodb_client.db

twine = Twine()
A_private_key = exchangeKeys.generate_key()

ka = ''

@app.route('/asconEncrypt', methods=['POST'])
def encrypt1():
    if(request.method == 'POST'):

        plaintext = request.json['plaintext']

        keysize = 16

        key = ascon.get_random_bytes(keysize)  # zero_bytes(keysize)
        nonce = ascon.get_random_bytes(16)      # zero_bytes(16)

        print(ascon.bytes_to_hex(key))
        print(ascon.bytes_to_hex(nonce))

        associateddata = b"ASCON"

        plaintext = plaintext.encode('UTF-8')

        ciphertext = ascon.ascon_encrypt(key, associateddata, nonce, plaintext)

        receivedplaintext = ascon.ascon_decrypt(key, associateddata, nonce, ciphertext)

        print(receivedplaintext.decode('UTF-8'))

        # print(bytes_to_hex(ciphertext))

        return jsonify({'encryptedText': ascon.bytes_to_hex(ciphertext)})


@app.route('/asconDecrypt', methods=['POST'])
def decrypt1():
    if(request.method == 'POST'):
        
        associateddata = b"ASCON"

        ciphertext = bytes.fromhex(request.json['ciphertext'])
        key = bytes.fromhex(request.json['key'])
        nonce = bytes.fromhex(request.json['nonce'])

        receivedplaintext = ascon.ascon_decrypt(key, associateddata, nonce, ciphertext)

        return jsonify({'decryptedText': receivedplaintext.decode('UTF-8')})

@app.route('/connect', methods=['GET'])
def conn():
    if(request.method == 'GET'):

        A_public_key = 23
        B_public_key = 9

        x = exchangeKeys.key_exchange_send_A(B_public_key, A_private_key, A_public_key)

        db.data.replace_one({'_id': ObjectId('61acdd4e8942a7b13bf0face')},{'x': x})

        return jsonify({'mssg': 'connected to B'})

@app.route('/sendData', methods=['POST'])
def sendMessg():
    if(request.method == 'POST'):

        res = db.data.find({'_id': ObjectId("61acdd5abbafce40f8046464") },{'_id':0,'x':0})

        A_public_key = 23

        global ka

        ka = exchangeKeys.key_exchange_recv_A(res[0]['y'], A_private_key, A_public_key)

        # print(ka)

        plaintext = request.json['plaintext']

        ciphertext = twine.encrypt(plaintext, ka)

        # print(ciphertext)

        # print(twine.decrypt(ciphertext, ka))

        db.mssg.replace_one({'_id': ObjectId("61ad12cc1ac829c575e85867")},{'mssgToB': ciphertext})
        
        return jsonify({'mssg': 'message sent to B'})

@app.route('/receiveData', methods=['GET'])
def receiveMessg():
    if(request.method == 'GET'):

        # print(ka)

        ciphertext = db.mssg.find({'_id': ObjectId("61ad12d31ac829c575e85868")},{'_id': 0})[0]['mssgToA']

        plaintext = twine.decrypt(ciphertext, ka)

        # print(plaintext)

        return jsonify({'mssg': plaintext})

@app.route('/', methods=['GET'])
def home():
    if(request.method == 'GET'):
        
        return jsonify({'mssg': 'working'})


# driver function
if __name__ == '__main__':
    app.run(debug=True)

