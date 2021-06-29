import json
import hmac
import hashlib
import os

from flask import Flask
from flask import request

config_api_key = 'k12345'
config_api_secret = 's12345'.encode('utf-8')


def loadDB():
    try:
        f = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'db.json')
        print('load db from %s...' % f)
        with open(f, 'rb') as fp:
            return json.load(fp)
    except Exception:
        return {}


def saveDB():
    try:
        f = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'db.json')
        print('save db to %s...' % f)
        with open(f, 'w') as fp:
            return json.dump(db, fp, indent=4)
    except Exception as e:
        print(e)
        print('save db failed.')


db = loadDB()


def processCreateGroup(id, params):
    tribeGroupId = params['tribeGroupId']
    tribeAddress = params['tribeAddress']
    if not tribeGroupId in db:
        db[tribeGroupId] = {
            'tribeAddress': tribeAddress,
            'members': {}
        }
        address = params['address']
        username = params['username']
        role = params['role']
        owner = params['owner']
        user = {
            'address': address,
            'username': username,
            'role': role,
            'owner': owner
        }
        db[tribeGroupId]['members'][address] = user
        saveDB()
    return json_success(id, {})


def processRemoveGroup(id, params):
    tribeGroupId = params['tribeGroupId']
    if tribeGroupId in db:
        del db[tribeGroupId]
        saveDB()
    return json_success(id, {})


def processAddMember(id, params):
    tribeGroupId = params['tribeGroupId']  # tribeGroupId
    address = params['address']  # 0x
    username = params['username']  # @username
    role = params['role']  # 0xff
    if tribeGroupId in db:
        user = {
            'address': address,
            'username': username,
            'role': role
        }
        db[tribeGroupId]['members'][address] = user
        saveDB()
        return json_success(id, {})
    return json_error(id, 100, 'tribeGroupId not found')


processUpdateMember = processAddMember


def processRemoveMember(id, params):
    tribeGroupId = params['tribeGroupId']  # 0xtribeGroupIdAddress
    address = params['address']  # 0x
    username = params['username']  # @username
    if tribeGroupId in db:
        del db[tribeGroupId]['members'][address]
        saveDB()
    return json_success(id, {})


def processNotifyMember(id, params):
    tribeGroupId = params['tribeGroupId']  # 0xtribeGroupIdAddress
    address = params['address']  # 0x
    username = params['username']  # @username
    message = params['message']  # message
    if tribeGroupId in db:
        if address in db[tribeGroupId]['members']:
            user = db[tribeGroupId]['members'][address]
            print('notify user %s: %s' % user.username, message)
            return json_success(id, {})
        return json_error(id, 200, 'member not found')
    return json_error(id, 100, 'tribeGroupId not found')


app = Flask(__name__)


@app.route('/')
def hello_world():
    return db


@app.route('/rpc', methods=['POST'])
def json_rpc():
    app.logger.info('process json-rpc request...')
    api_key = request.headers.get('API-Key') or ''
    api_timestamp = request.headers.get('API-Timestamp') or ''
    api_sign = request.headers.get('API-Signature') or ''
    # FIXME: check api-key, timestamp

    body = request.get_data()
    payload = api_key.encode('utf-8') + b'\n' + \
        api_timestamp.encode('utf-8') + b'\n' + body
    h = hmac.new(config_api_secret, payload, digestmod='SHA256')
    expected_sign = h.hexdigest()
    app.logger.info('JSON-RPC request:\nAPI-Key: %s\nAPI-Timestamp: %s\nAPI-Signature: %s\n%s',
                    api_key, api_timestamp, api_sign, body)
    app.logger.info('Expected signature: %s', expected_sign)

    req = json.loads(body)
    app.logger.info('JSON-RPC Request:\n%s', json.dumps(req, indent=4))

    method = req.get('method', '')
    if method == 'CREATE_GROUP':
        return processCreateGroup(req['id'], req['params'])

    if method == 'REMOVE_GROUP':
        return processRemoveGroup(req['id'], req['params'])

    if method == 'ADD_MEMBER':
        return processAddMember(req['id'], req['params'])

    if method == 'REMOVE_MEMBER':
        return processRemoveMember(req['id'], req['params'])

    if method == 'UPDATE_MEMBER':
        return processUpdateMember(req['id'], req['params'])

    if method == 'NOTIFY_MEMBER':
        return processNotifyMember(req['id'], req['params'])

    return json_error(req.get('id', 0), -32601, 'Unsupported method.')


def json_error(id, code, message):
    return {
        'id': id,
        'jsonrpc': '2.0',
        'error': {
            'code': code,
            'message': message
        }
    }


def json_success(id, data):
    return {
        'id': id,
        'jsonrpc': '2.0',
        'result': data
    }


def hash(s):
    md5 = hashlib.md5()
    md5.update(s.encode('utf-8'))
    return md5.hexdigest()
