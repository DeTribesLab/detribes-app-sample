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
    tribe = params['tribe']
    if not tribe in db:
        db[tribe] = {
            'group': hash(tribe),
            'members': {},
            'usernames': {}
        }
        saveDB()
    return json_success(id, {'group': db[tribe]['group']})


def processRemoveGroup(id, params):
    tribe = params['tribe']
    if tribe in db:
        del db[tribe]
        saveDB()
    return json_success(id, {})


def processAddMember(id, params):
    tribe = params['tribe']  # 0xTribeAddress
    member = params['member']  # 0xMemberAddress
    username = params['username']  # @username
    role = params['role']  # 0xff
    if tribe in db:
        ins = {
            'member': member,
            'username': username,
            'role': role
        }
        db[tribe]['members'][member] = ins
        db[tribe]['usernames'][username] = ins
        saveDB()
        return json_success(id, ins)
    return json_error(id, 100, 'tribe not found')


processUpdateMember = processAddMember


def processRemoveMember(id, params):
    tribe = params['tribe']  # 0xTribeAddress
    member = params['member']  # 0xMemberAddress
    username = params['username']  # @username
    if tribe in db:
        del db[tribe]['members'][member]
        del db[tribe]['usernames'][username]
        saveDB()
    return json_success(id, {})


def processNotifyMember(id, params):
    tribe = params['tribe']  # 0xTribeAddress
    member = params['member']  # 0xMemberAddress
    username = params['username']  # @username
    message = params['message']  # message
    if tribe in db:
        if member in db[tribe]['members']:
            user = db[tribe]['members'][member]
            print('notify user %s: %s' % member, message)
            return json_success(id, {})
        return json_error(id, 200, 'member not found')
    return json_error(id, 100, 'tribe not found')


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
