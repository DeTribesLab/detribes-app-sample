import json
import hmac
import logging
import hashlib
import asyncio

from flask import Flask, request

from telethon import TelegramClient
from telethon.tl.functions.channels import CreateChannelRequest, InviteToChannelRequest, DeleteChannelRequest

from sqlalchemy import Column, String, Integer, UniqueConstraint, Boolean, create_engine
from sqlalchemy.orm import sessionmaker, scoped_session, Session
from sqlalchemy.ext.declarative import declarative_base

# declare models
Base = declarative_base()

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


# load config
with open("config.json") as config_file:
    config = json.load(config_file)
print(config)

# initialize logger
logging.basicConfig(format='%(asctime)s %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p')
logger = logging.getLogger(__name__)

# initialize loop
loop = asyncio.get_event_loop()

# initialize db
engine = create_engine(config['mysql']['url'], echo=True, future=True)
Session = scoped_session(sessionmaker(bind=engine))

# initialize Telethon
telegram_app_id = config['telegram']['appId']
telegram_app_hash = config['telegram']['appHash']
telegram_bind_phone = config['telegram']['phone']
telegram_client = TelegramClient('Telegram Server', telegram_app_id, telegram_app_hash)
telegram_client.start(phone=telegram_bind_phone)

# initialize api
config_api_key = config['api']['key']
config_api_secret = config['api']['secret']

# initialize flask app
app = Flask(__name__)


def t_create_group(name, desc):
    create_channel_req = loop.run_until_complete(telegram_client(CreateChannelRequest(name, desc, megagroup=True)))
    return create_channel_req.__dict__["chats"][0].__dict__["id"]


def t_remove_group(channel_id):
    loop.run_until_complete(telegram_client(DeleteChannelRequest(channel_id)))


def t_get_entity(username):
    return loop.run_until_complete(telegram_client.get_entity(username))

def t_add_member(channel_id, user):
    return loop.run_until_complete(telegram_client(InviteToChannelRequest(channel_id, [user])))


def t_remove_member(channel_id, user):
    return loop.run_until_complete(telegram_client.edit_permissions(channel_id, user, view_messages=False))


def t_grant_admin(channel_id, user, is_owner=False):
    add_admins = True if is_owner else False
    return loop.run_until_complete(telegram_client.edit_admin(channel_id, user, is_admin=True, invite_users=False, add_admins=add_admins))


def t_revoke_admin(channel_id, user):
    return loop.run_until_complete(telegram_client.edit_admin(channel_id, user, is_admin=False))


def t_send_message(user, msg):
    return loop.run_until_complete(telegram_client.send_message(user, msg))

def get_channel(session: Session, tribe_group_id: str, allow_not_found: bool) -> Channel:
    try:
        channel = session.query(Channel).filter(Channel.tribeGroupId == tribe_group_id).one()
    except Exception as e:
        if allow_not_found:
            return None
        raise Exception('Channel[{}] not found'.format(tribe_group_id))
    return channel


def get_member(session: Session, tribe_group_id:str, username: str, address: str, allow_not_found: bool) -> Member:
    try:
        member = session.query(Member).filter(
            Member.tribeGroupIdId == tribe_group_id,
            Member.username == username,
            Member.address == address).one()
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
    channel = get_channel(tribe_group_id, True)

    if channel:
        raise Exception('Channel[{}] exists'.format(tribe_group_id))

    # create channel
    channel_id = t_create_group(name, description)

    # add channel to DB
    channel = Channel(
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
    user = t_get_entity(params.get('username', None))

    t_add_member(channel_id, user)

    # set member to owner
    t_grant_admin(channel_id, user, is_owner=True)

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
    session.add(member)
    return json_success(rpc_id, {})


def process_remove_group(session: Session, rpc_id: int, params: dict) -> None:
    tribe_group_id = params['tribeGroupId']
    channel = get_channel(session, tribe_group_id)
    # remove channel from telegram
    t_remove_group(channel_id=channel.channelId)
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

    channel = get_channel(tribe_group_id)

    # handle owner
    if owner:
        owner_member = session(Member).filter(Member.tribeGroupIdId == tribe_group_id, Member.owner).first()

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
    session.add(member)

    # add member to Channel
    t_add_member(channel_id=channel.channelId, user=t_get_entity(username))
    if owner:
        t_grant_admin(channel_id=channel.channelId, is_owner=True)
    elif role > 0:
        t_grant_admin(channel_id=channel.channelId, is_owner=False)

    return json_success(rpc_id, {})


def process_update_member(session:Session, rpc_id, params):
    tribe_group_id = params['tribeGroupId']
    username = params['username']
    address = params['address']
    role = params.get('role', 0) # 0xff
    expires = params.get('expires', 0)

    member = session(Member).filter(
        Member.tribeGroupIdId == tribe_group_id,
        Member.username == username,
        Member.address == address).one()
    channel = session(Channel).filter(Channel.tribeGroupIdId == tribe_group_id).one()

    member.role = role
    member.expires = expires

    user = t_get_entity(username)

    if member.role > 0 and role == 0:
        # revoke admin
        t_revoke_admin(channel_id=channel.channelId, user=user)
    if member.role == 0 and role > 0:
        # grant admin
        t_grant_admin(channel_id=channel.channelId, user=user, is_owner=False)

    session.add(member)
    return json_success(rpc_id, {})


def process_remove_member(session:Session, rpc_id, params):
    tribe_group_id = params['tribeGroupId']  # 0xtribeGroupIdAddress
    username = params['username']  # @username
    address = params['address']
    # delete us
    session(Member).filter(
        Member.tribeGroupIdId == tribe_group_id,
        Member.address == address,
        Member.username == username
    ).delete()

    # remove from channel if username not exists
    if Session(Member).filter(Member.tribeGroupIdId == tribe_group_id, Member.username == username).count() == 0:
        channel = get_channel(session, tribe_group_id)
        user = t_get_entity(username)
        t_remove_member(channel_id=channel.channelId, user=user)
    return json_success(rpc_id, {})


def process_notify_member(session: Session, rpc_id, params):
    tribe_group_id = params['tribeGroupId']  # 0xtribeGroupIdAddress
    channel = get_channel(session, tribe_group_id)
    address = params['address']  # 0xMemberAddress
    username = params['username']  # @username
    message = params['message']  # message
    if not username:
        raise Exception('username not found')
    user = t_get_entity(username)
    t_send_message(user, message)
    return json_success(rpc_id, {})


@app.before_first_request
def startup():
    telegram_client.start(phone=telegram_bind_phone)


@app.be
def cleanup():
    loop.run_until_complete(telegram_client.disconnect())



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
        session = Session()
        handlers[method](session, rpc_id, req['params'])
        session.commit()
    except Exception as e:
        return json_error(rpc_id, -10000, str(e))
    finally:
        Session.remove()


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
