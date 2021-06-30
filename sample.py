import json
import hmac
import hashlib
import logging
import os

from flask import Flask, g
from flask import request

# set sync mode
from telethon.sync import TelegramClient
from telethon.tl.functions.channels import CreateChannelRequest, InviteToChannelRequest, DeleteChannelRequest

import pymysql

logger = logging.getLogger()

# load config
with open("config.json") as config_file:
    config = json.load(config_file)
print(config)
# create sqlalchemy
from sqlalchemy import create_engine, Column, String, Integer, UniqueConstraint, Boolean
from sqlalchemy.orm import scoped_session, sessionmaker
from sqlalchemy.ext.declarative import declarative_base
engine = create_engine(config['mysql']['url'], convert_unicode=True)
db_session = scoped_session(sessionmaker(autoflush=False, autocommit=False, bind=engine))
print('db_session created')
Base = declarative_base()
Base.query = db_session.query_property()


class Channel(Base):
    __tablename__ = 'channels'
    tribeGroupIdId = Column('tribeGroupIdId', String(100), nullable=False, primary_key=True)
    tribeAddress = Column('tribeAddress', String(42), nullable=False)
    channelId = Column('channelId', String(100), nullable=False)
    name = Column('name', String(100), nullable=False)
    description = Column('description', String(100), nullable=False)


class Member(Base):
    __tablename__ = 'members'
    id = Column('id', Integer, autoincrement=True, primary_key=True)
    tribeGroupIdId = Column('tribeGroupIdId', String(100), nullable=False, primary_key=True)
    address = Column('address', String(42), nullable=False)
    username = Column('username', String(100), nullable=False)
    role = Column('role', Integer, nullable=False, default=0)
    expires = Column('expires', Integer, nullable=False, default=0)
    description = Column('description', String(100), nullable=False, default='')
    owner = Column('owner', Boolean, default=False)
    UniqueConstraint('tribeGroupId', 'address', 'username', name='UNI_ADDR_USER')


# initialize Telethon
telegram_app_id = config['telegram']['appId']
telegram_app_hash = config['telegram']['appHash']
telegram_bind_phone = config['telegram']['phone']
print('before connect telegram client')
telegram_client = TelegramClient('Telegram Server', telegram_app_id, telegram_app_hash)
client = telegram_client.connect()

print('telegram connected')

config_api_key = config['api']['key']
config_api_secret = config['api']['secret']


def get_channel(tribe_group_id: str, allow_not_found: bool) -> Channel:
    try:
        channel = Channel.query.filter(Channel.tribeGroupId == tribe_group_id).one()
    except Exception as e:
        if allow_not_found:
            return None
        raise Exception('Channel[{}] not found'.format(tribe_group_id))
    return channel


def get_member(tribe_group_id:str, username: str, address: str, allow_not_found: bool) -> Member:
    try:
        member = Member.query.filter(
            Member.tribeGroupIdId == tribe_group_id,
            Member.username == username,
            Member.address == address).one()
    except Exception as e:
        if allow_not_found:
            return None
        raise Exception('Channel[{}] Member[{}:{}] not found', tribe_group_id, username, address)
    return member


def process_create_group(rpc_id: int, params: dict) -> None:
    tribe_group_id = params.get('tribeGroupId', None)
    tribe_address = params.get('tribeAddress', None)
    name = params.get('name', '')
    description = params.get('description', '')
    print(params)
    channel = get_channel(tribe_group_id, True)

    if channel:
        raise Exception('Channel[{}] exists'.format(tribe_group_id))

    # create channel
    create_channel_req = telegram_client(CreateChannelRequest(params['name'], params['description'], megagroup=True))
    channel_id = create_channel_req.__dict__["chats"][0].__dict__["id"]

    # add channel to DB
    channel = Channel(
        tribeGroupId=tribe_group_id,
        tribeAddress=tribe_address,
        channelId=channel_id,
        name=name,
        description=description
    )
    db_session.add(channel)

    # add member to channel
    username = params.get('username', '')
    user = telegram_client.get_entity(username)
    telegram_client(InviteToChannelRequest(channel_id, [user]))

    # set member to owner
    telegram_client.edit_admin(channel_id, user, is_admin=True, invite_users=False, add_admins=True)

    address = params.get('address', '')
    role = params.get('role', 0)
    expires = params.get('expires', 0)

    # add member to DB
    member = Member(
        tribeGroupIdId=tribe_group_id,
        address=address,
        username=username,
        role=role,
        expires=expires,
        owner=True
    )
    db_session.add(member)
    return json_success(rpc_id, {})


def process_remove_group(rpc_id: int, params: dict) -> None:
    tribe_group_id = params['tribeGroupId']
    channel = get_channel(tribe_group_id)
    # update telegram
    telegram_client(DeleteChannelRequest(channel.channelId))
    return json_success(rpc_id, {})


def process_add_member(rpc_id: int, params: dict) -> None:
    tribe_group_id = params['tribeGroupId']  # 0xtribeGroupIdAddress
    username = params['username'] # @username
    address = params['address']
    role = params.get('role', 0)  # 0xff
    expires = params.get('expires', 0) # never expire
    owner = params.get('owner', False)

    channel = get_channel(tribe_group_id)

    # handle owner
    if owner:
        owner_member = Member.query.filter(Member.tribeGroupIdId == tribe_group_id, Member.owner).first()

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
    member = Member(tribeGroupIdId=tribe_group_id, address=address, username=username, role=role, expires=expires, owner=owner)
    db_session.add(member)

    # add member to Channel
    user = telegram_client.get_entity(username)
    telegram_client(InviteToChannelRequest(channel.channelId, [user]))

    if owner:
        telegram_client.edit_admin(channel.channelId, user, is_admin=True, invite_users=False, add_admins=True)
    elif role > 0:
        telegram_client.edit_admin(channel.channelId, user, is_admin=True, invite_users=False, add_admins=False)

    return json_success(rpc_id, {})


def process_update_member(rpc_id, params):
    tribe_group_id = params['tribeGroupId']
    username = params['username']
    address = params['address']
    role = params.get('role', 0) # 0xff
    expires = params.get('expires', 0)

    member = Member.query.filter(
        Member.tribeGroupIdId == tribe_group_id,
        Member.username == username,
        Member.address == address).one()
    channel = Channel.query.filter(Channel.tribeGroupIdId == tribe_group_id).one()

    member.role = role
    member.expires = expires

    user = telegram_client.get_entity(username)

    if member.role > 0 and role == 0:
        # revoke admin
        telegram_client.edit_admin(channel.channelId, user, is_admin=False)
    if member.role == 0 and role > 0:
        # grant admin
        telegram_client.edit_admin(channel.channelId, user, is_admin=True, invite_users=False, add_admins=False)

    db_session.add(member)
    return json_success(rpc_id, {})


def process_remove_member(rpc_id, params):
    tribe_group_id = params['tribeGroupId']  # 0xtribeGroupIdAddress
    username = params['username']  # @username
    address = params['address']
    # delete us
    Member.query.filter_by(
        Member.tribeGroupIdId == tribe_group_id,
        Member.address == address,
        Member.username == username
    ).delete()

    # remove from channel if username not exists
    if Member.query.filter(Member.tribeGroupIdId == tribe_group_id, Member.username == username).count() == 0:
        channel = get_channel(tribe_group_id)
        user = telegram_client.get_entity(username)
        telegram_client.edit_permissions(channel.channelId, user, view_messages=False)
    return json_success(rpc_id, {})


def process_notify_member(rpc_id, params):
    tribe_group_id = params['tribeGroupId']  # 0xtribeGroupIdAddress
    channel = get_channel(tribe_group_id)
    address = params['address']  # 0xMemberAddress
    username = params['username']  # @username
    message = params['message']  # message
    user = telegram_client.get_entity(username)
    telegram_client.send_message(user, message)
    return json_success(rpc_id, {})

app = Flask(__name__)


@app.teardown_request
def shutdown_session(exception=None):
    if exception:
        db_session.rollback()
    else:
        db_session.commit()
    db_session.remove()


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
        handlers[method](rpc_id, req['params'])
    except Exception as e:
        return json_error(rpc_id, -10000, str(e))


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
