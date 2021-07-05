import json
import hmac
import hashlib
import atexit

from flask import Flask, request
from sqlalchemy.orm import Session

from config import config
import telegram
import db

# initialize api
config_api_key = config['api']['key']
config_api_secret = config['api']['secret']

# initialize flask app
app = Flask(__name__)


def get_channel(session: Session, tribe_group_id: str, allow_not_found=False) -> db.Channel:
    try:
        channel = session.query(db.Channel).filter(db.Channel.tribeGroupId == tribe_group_id).one()
    except Exception as e:
        if allow_not_found:
            return None
        raise Exception('Channel[{}] not found'.format(tribe_group_id))
    return channel


def get_member(session: Session, tribe_group_id:str, username: str, address: str, allow_not_found: bool) -> db.Member:
    try:
        member = session.query(db.Member).filter(
            db.Member.tribeGroupIdId == tribe_group_id,
            db.Member.username == username,
            db.Member.address == address).one()
    except Exception as e:
        if allow_not_found:
            return None
        raise Exception('Channel[{}] Member[{}:{}] not found', tribe_group_id, username, address)
    return member


def process_create_group(session: Session, rpc_id: int, params: dict) -> None:
    tribe_group_id = params.get('tribeGroupId', None)
    tribe_address = params.get('tribeAddress', None)
    name = params.get('name', '')
    description = params.get('description', '')
    print(params)
    channel = get_channel(session, tribe_group_id, True)

    if channel:
        raise Exception('Channel[{}] exists'.format(tribe_group_id))

    # create channel
    channel_id = telegram.create_group(name, description)

    # add channel to DB
    channel = db.Channel(
        tribeGroupId=tribe_group_id,
        tribeAddress=tribe_address,
        channelId=channel_id,
        name=name,
        description=description
    )
    session.add(channel)

    # add member to channel
    username = params.get('username', None)
    if not username:
        raise Exception('username not found')
    user = telegram.get_entity(params.get('username', None))

    telegram.add_member(channel_id, user)

    # set member to owner
    telegram.grant_admin(channel_id, user, is_owner=True)

    address = params.get('address', '')
    role = params.get('role', 0)
    expires = params.get('expires', 0)

    # add member to DB
    member = db.Member(
        tribeGroupIdId=tribe_group_id,
        address=address,
        username=username,
        role=role,
        expires=expires,
        owner=True
    )
    session.add(member)
    return json_success(rpc_id, {})


def process_remove_group(session: Session, rpc_id: int, params: dict) -> None:
    tribe_group_id = params['tribeGroupId']
    channel = get_channel(session, tribe_group_id)
    # remove channel from telegram
    telegram.remove_group(channel_id=channel.channelId)
    # update db
    session.delete(channel)

    return json_success(rpc_id, {})


def process_add_member(session: Session, rpc_id: int, params: dict) -> None:
    tribe_group_id = params['tribeGroupId']  # 0xtribeGroupIdAddress
    username = params['username'] # @username
    address = params['address']
    role = params.get('role', 0)  # 0xff
    expires = params.get('expires', 0) # never expire
    owner = params.get('owner', False)

    channel = get_channel(session, tribe_group_id)

    # handle owner
    if owner:
        owner_member = session(db.Member).filter(db.Member.tribeGroupIdId == tribe_group_id, db.Member.owner).first()

        # joined and set to owner
        if owner_member:
            if not owner_member.username == username or not owner_member.address == address:
                # owner is other member, owner transferring flow is 1. remove owner 2. add new owner
                raise Exception(
                    'Channel[{}] Owner[{}:{}] exists'.format(
                        tribe_group_id,
                        owner_member.username,
                        owner_member.address))

    # save member to DB
    member = db.Member(tribeGroupIdId=tribe_group_id, address=address, username=username, role=role, expires=expires, owner=owner)
    session.add(member)

    # add member to Channel
    telegram.add_member(channel_id=channel.channelId, user=telegram.get_entity(username))
    if owner:
        telegram.grant_admin(channel_id=channel.channelId, is_owner=True)
    elif role > 0:
        telegram.grant_admin(channel_id=channel.channelId, is_owner=False)

    return json_success(rpc_id, {})


def process_update_member(session:Session, rpc_id, params):
    tribe_group_id = params['tribeGroupId']
    username = params['username']
    address = params['address']
    role = params.get('role', 0) # 0xff
    expires = params.get('expires', 0)

    member = session(db.Member).filter(
        db.Member.tribeGroupIdId == tribe_group_id,
        db.Member.username == username,
        db.Member.address == address).one()
    channel = session(db.Channel).filter(db.Channel.tribeGroupIdId == tribe_group_id).one()

    member.role = role
    member.expires = expires

    user = telegram.get_entity(username)

    if member.role > 0 and role == 0:
        # revoke admin
        telegram.revoke_admin(channel_id=channel.channelId, user=user)
    if member.role == 0 and role > 0:
        # grant admin
        telegram.grant_admin(channel_id=channel.channelId, user=user, is_owner=False)

    session.add(member)
    return json_success(rpc_id, {})


def process_remove_member(session:Session, rpc_id, params):
    tribe_group_id = params['tribeGroupId']  # 0xtribeGroupIdAddress
    username = params['username']  # @username
    address = params['address']
    # delete us
    session(db.Member).filter(
        db.Member.tribeGroupIdId == tribe_group_id,
        db.Member.address == address,
        db.Member.username == username
    ).delete()

    # remove from channel if username not exists
    if Session(db.Member).filter(db.Member.tribeGroupIdId == tribe_group_id, db.Member.username == username).count() == 0:
        channel = get_channel(session, tribe_group_id)
        user = telegram.get_entity(username)
        telegram.remove_member(channel_id=channel.channelId, user=user)
    return json_success(rpc_id, {})


def process_notify_member(session: Session, rpc_id, params):
    tribe_group_id = params['tribeGroupId']  # 0xtribeGroupIdAddress
    channel = get_channel(session, tribe_group_id)
    address = params['address']  # 0xMemberAddress
    username = params['username']  # @username
    message = params['message']  # message
    if not username:
        raise Exception('username not found')
    user = telegram.get_entity(username)
    telegram.send_message(user, message)
    return json_success(rpc_id, {})


# @atexit.register
# def cleanup():
#     # loop.run_until_complete(telegram.disconnect())
#     db.engine.dispose()


@app.route('/rpc', methods=['POST'])
def json_rpc():
    app.logger.info('process json-rpc request...')
    # api_key = request.headers.get('API-Key') or ''
    # api_timestamp = request.headers.get('API-Timestamp') or ''
    # api_sign = request.headers.get('API-Signature') or ''
    # # FIXME: check api-key, timestamp
    #
    body = request.get_data()
    # payload = api_key.encode('utf-8') + b'\n' + \
    #           api_timestamp.encode('utf-8') + b'\n' + body
    # h = hmac.new(config_api_secret, payload, digestmod='SHA256')
    # expected_sign = h.hexdigest()
    # app.logger.info('JSON-RPC request:\nAPI-Key: %s\nAPI-Timestamp: %s\nAPI-Signature: %s\n%s',
    #                 api_key, api_timestamp, api_sign, body)
    # app.logger.info('Expected signature: %s', expected_sign)

    req = json.loads(body)
    app.logger.info('JSON-RPC Request:\n%s', json.dumps(req, indent=4))

    method = req.get('method', '')
    rpc_id = req.get('id', 0)

    handlers = dict(
        CREATE_GROUP=process_create_group,
        REMOVE_GROUP=process_remove_group,
        ADD_MEMBER=process_add_member,
        REMOVE_MEMBER=process_remove_member,
        UPDATE_MEMBER=process_update_member,
        NOTIFY_MEMBER=process_notify_member
    )

    if method not in handlers:
        return json_error(req.get('id', rpc_id), -32601, 'Unsupported method.')
    try:
        session = db.Session()
        handlers[method](session, rpc_id, req['params'])
        session.commit()
    except Exception as e:
        return json_error(rpc_id, -10000, str(e))
    finally:
        db.Session.remove()


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


if __name__ == '__main__':
    telegram.initialize()
    app.run(host='0.0.0.0', port=5000, debug=True, use_reloader=False)