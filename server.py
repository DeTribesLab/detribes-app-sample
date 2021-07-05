from datetime import timedelta
import json
import time, datetime

from telethon import utils

from telethon.sync import TelegramClient
from telethon.tl.functions import channels
from telethon.tl.functions.channels import (
    CreateChannelRequest,
    EditBannedRequest,
    InviteToChannelRequest,
    DeleteChannelRequest,
)
import aiomysql

from quart import Quart, request

import hypercorn
from logging.config import dictConfig

from telethon.tl.types import ChatBannedRights

# initial logger
dictConfig(
    {
        "version": 1,
        "loggers": {
            "quart.app": {
                "level": "INFO",
            },
        },
    }
)


# load config
with open("config.json") as config_file:
    config = json.load(config_file)
    print(config)

# Telethon client
telegram_app_id = config["telegram"]["appId"]
telegram_app_hash = config["telegram"]["appHash"]
telegram_bind_phone = config["telegram"]["phone"]
client = TelegramClient("Telegram", telegram_app_id, telegram_app_hash)

# db
mysql_host = config["mysql"]["host"]
mysql_port = config["mysql"]["port"]
mysql_user = config["mysql"]["user"]
mysql_password = config["mysql"]["password"]
mysql_db = config["mysql"]["db"]

pool = None


async def setup_db(loop):
    global pool
    pool = await aiomysql.create_pool(
        echo=True,
        host=mysql_host,
        port=mysql_port,
        user=mysql_user,
        password=mysql_password,
        db=mysql_db,
        loop=loop,
    )
    app.logger.info("connected db")


async def close_db():
    global pool
    pool.close()
    await pool.wait_closed()
    app.logger.info("closed db")


# logic


def to_dict(columns, row):
    if not row:
        return None
    return dict(zip(columns, row))


async def get_channel(cursor, tribe_group_id):
    get_channel_by_id_sql = """
    select tribeGroupId, tribeAddress, channelId, name, description from channels where tribeGroupId=%s
    """
    await cursor.execute(get_channel_by_id_sql, tribe_group_id)
    columns = [column[0] for column in cursor.description]
    return to_dict(columns, await cursor.fetchone())


async def get_member(cursor, tribe_group_id, username, address):
    get_member_by_username_address_sql = """
    select id, tribeGroupId, address, username, userId, role, expires, metadata, owner from members where tribeGroupId=%s and username=%s and address=%s
    """
    await cursor.execute(
        get_member_by_username_address_sql, (tribe_group_id, username, address)
    )
    columns = [column[0] for column in cursor.description]
    return to_dict(columns, await cursor.fetchone())


async def add_channel(
    cursor, tribe_group_id, tribe_address, channel_id, name, description
):
    insert_channel_sql = """
    insert into channels (tribeGroupId, tribeAddress, channelId, name, description) values (%s, %s, %s, %s, %s)
    """
    await cursor.execute(
        insert_channel_sql,
        (tribe_group_id, tribe_address, channel_id, name, description),
    )


async def remove_channel(cursor, tribe_group_id):
    remove_channel_sql = """
    delete from channels where tribeGroupId=%s
    """
    remove_channel_member_sql = """
    delete from members where tribeGroupId=%s
    """
    await cursor.execute(remove_channel_sql, tribe_group_id)
    await cursor.execute(remove_channel_member_sql, tribe_group_id)


async def add_member(
    cursor, tribe_group_id, username, address, user_id, expires, role=0, owner=False, metadata=""
):
    insert_member_sql = """
    insert into members (tribeGroupId, username, address, userId, role, expires, owner, metadata) values (%s, %s, %s, %s, %s, %s, %s, %s)
    """
    await cursor.execute(
        insert_member_sql,
        (
            tribe_group_id,
            username,
            address,
            user_id,
            role,
            expires,
            owner,
            metadata,
        ),
    )


async def update_member(
    cursor, tribe_group_id, username, address, expires, role, metadata
):
    update_member_sql = """
    update members set username=%s, address=%s, expires=%s, owner=%s,metadata=%s where tribeGroupId=%s and username=%s and address=%s
    """
    await cursor.execute(
        update_member_sql,
        (username, address, expires, role, metadata, tribe_group_id, username, address),
    )

async def remove_member(cursor, tribe_group_id, username, address):
    remove_member_sql="""
    delete from members where tribeGroupId=%s and username=%s and address=%s
    """
    await cursor.execute(remove_member_sql, (tribe_group_id, username, address))

async def process_create_group(cursor, params: dict) -> None:
    tribe_group_id = params.get("tribeGroupId", None)
    tribe_address = params.get("tribeAddress", None)
    name = params.get("name", None)
    description = params.get("description", None)

    if not tribe_group_id:
        raise Exception("tribeGroupId is None")
    if not tribe_address:
        raise Exception("tribeAddress is None")

    channel = await get_channel(cursor, tribe_group_id)
    if channel:
        raise Exception("tribeGroupId[{}] exists".format(tribe_group_id))
    req = await client(CreateChannelRequest(name, description, megagroup=True))
    channel_id = req.__dict__["chats"][0].__dict__["id"]
    await add_channel(
        cursor, tribe_group_id, tribe_address, channel_id, name, description
    )

    username = params.get("username", None)
    if not username:
        raise Exception("username is None")
    address = params.get("address", None)
    if not address:
        raise Exception("address is None")

    user = await client.get_entity(username)
    await client(InviteToChannelRequest(channel_id, [user]))
    metadata = params.get('metadata', "")
    expires = params.get('expires', 0)
    if expires < int(time.time()):
        raise Exception('username [{}] expires [{}] before now'.format(username, expires))
    await add_member(cursor, tribe_group_id, username, address, user.id, expires, 0, True, metadata)
    return dict(channelId=channel_id, userId=user.id)


async def process_remove_group(cursor, params):
    tribe_group_id = params.get("tribeGroupId", None)
    channel = await get_channel(cursor, tribe_group_id)
    if not channel:
        raise Exception("tribeGroupId not found")
    await client(DeleteChannelRequest(channel['channelId']))
    await remove_channel(cursor, tribe_group_id)
    app.logger.info('remove group [{}], telegram channel [{}]'.format(tribe_group_id, channel['channelId']))
    return dict(tribeGroupId=tribe_group_id)


async def process_add_member(cursor, params):
    tribe_group_id = params.get("tribeGroupId", None)
    username = params.get('username', None)
    address = params.get('address', None)
    if not tribe_group_id:
        raise Exception('tribeGroupId not exists')
    
    if not username:
        raise Exception('username not exists')

    if not address:
        raise Exception('address not exists')
    
    channel = await get_channel(cursor, tribe_group_id)
    if not channel:
        raise Exception('tribeGroupId[{}] not created'.format(tribe_group_id))
    
    user = await client.get_entity(username)
    app.logger.info('username {} userId {}'.format(username, user.id))
    member = await get_member(cursor, tribe_group_id, user.id)
    if member:
        raise Exception('member[{},{}] already joined in group[{}]'.format(username, address, tribe_group_id))
    
    await client(InviteToChannelRequest(channel['channelId'], [user]))

    rights = ChatBannedRights(
        utils_date=datetime.now() + timedelta(weeks=10000),
        send_polls=False
    )
    await client(EditBannedRequest(channel['channelId'], user, rights))

    role = params.get('role', 0)
    metadata = params.get('metadata', '')
    expires = params.get('expires', 0)

    if expires < int(time.time()):
        raise Exception('username [{}] expires [{}] before now'.format(username, expires))

    if role > 0:
        await client.edit_admin(channel["channelId"], user, is_admin=True, invite_users=False, add_admins=False)

    await add_member(cursor, tribe_group_id, username, address, user.id, expires, metadata=metadata)
    return dict(tribeGroupId=tribe_group_id, userId=user.id)


async def process_update_member(cursor, params):
    tribe_group_id = params.get("tribeGroupId", None)
    username = params.get('username', None)
    address = params.get('address', None)
    
    if not tribe_group_id:
        raise Exception('tribeGroupId not exists')
    
    if not username:
        raise Exception('username not exists')
    
    if not address:
        raise Exception('address not exists')

    user = await client.get_entity(username)

    app.logger.info('username {} userId {}'.format(username, user.id))

    channel = await get_channel(cursor, tribe_group_id)

    if not channel:
        raise Exception('tribeGroupId[{}] not found'.format(tribe_group_id))

    member = await get_member(cursor, tribe_group_id, username, address)
    
    if not member:
        raise Exception('member [{}, {}, {}] not found'.format(tribe_group_id, username, address))

    role = params.get('role', 0)
    metadata = params.get('metadata', '')
    expires = params.get('expires', 0)
    
    if expires < int(time.time()):
        raise Exception('username [{}] expires [{}] before now'.format(username, expires))

    if member['role'] == 0 and role > 0:
        # upgrade Admin
        await client.edit_admin(channel['channelId'],  user, is_admin=True, invite_users=False, add_admins=False)
        app.logger.info('upgrade member[{},{}] in group [{}] to admin'.format(username, address, tribe_group_id))

    if member['role'] > 0 and role == 0:
        # downgrade general user
        await client.edit_admin(channel['channelId'], user, is_admin=False)
        app.logger.info('downgrade member[{},{}] in group [{}] to general account'.format(username, address, tribe_group_id))

    await update_member(cursor, tribe_group_id, username, address, expires, role, metadata)


async def process_remove_member(cursor, params):
    tribe_group_id = params.get("tribeGroupId", None)
    username = params.get('username', None)
    address = params.get('address', None)

    if not tribe_group_id:
        raise Exception('tribeGroupId not exists')
    
    if not username:
        raise Exception('username not exists')
    
    if not address:
        raise Exception('address not exists')

    user = await client.get_entity(username)

    channel = await get_channel(cursor, tribe_group_id)

    if not channel:
        raise Exception('tribeGroupId[{}] not found'.format(tribe_group_id))

    await client.edit_permissions(channel['channelId'], user, view_messages=False)
    await remove_member(cursor, tribe_group_id, username, address)


async def process_notify_member(cursor, params):
    tribe_group_id = params.get("tribeGroupId", None)
    username = params.get('username', None)
    address = params.get('address', None)

    if not tribe_group_id:
        raise Exception('tribeGroupId not exists')
    
    if not username:
        raise Exception('username not exists')
    
    if not address:
        raise Exception('address not exists')

    channel = await get_channel(cursor, tribe_group_id)
    if not channel:
        raise Exception('tribeGroupId[{}] not found'.format(tribe_group_id))
    
    user = await client.get_entity(username)

    await client.send_message(user, params.get('message', ""))


async def process_notify_group(cursor, params):
    tribe_group_id = params.get("tribeGroupId", None)
    if not tribe_group_id:
        raise Exception('tribeGroupId not exists')

    channel = await get_channel(cursor, tribe_group_id)
    if not channel:
        raise Exception('tribeGroupId[{}] not found'.format(tribe_group_id))
    
    # user = await client.get_entity(username)

    await client.send_message(channel['channelId'], params.get('message', ""))


# Quart app
app = Quart(__name__)
app.secret_key = "CHANGE THIS TO SOMETHING SECRET"


@app.before_serving
async def startup():
    if not await client.connect():
        await client.start(phone=telegram_bind_phone)
    await setup_db(client.loop)
    app.logger.info("startup finished")


@app.after_serving
async def cleanup():
    await client.disconnect()
    app.logger.info('telegram client disconnected')
    await close_db()
    app.logger.info('database disconnected')
    app.logger.info("cleanup finished")


@app.route("/rpc", methods=["POST"])
async def rpc():
    app.logger.info("process json-rpc request...")
    # api_key = request.headers.get('API-Key') or ''
    # api_timestamp = request.headers.get('API-Timestamp') or ''
    # api_sign = request.headers.get('API-Signature') or ''
    # # FIXME: check api-key, timestamp
    #
    body = await request.get_data()
    # payload = api_key.encode('utf-8') + b'\n' + \
    #           api_timestamp.encode('utf-8') + b'\n' + body
    # h = hmac.new(config_api_secret, payload, digestmod='SHA256')
    # expected_sign = h.hexdigest()
    # app.logger.info('JSON-RPC request:\nAPI-Key: %s\nAPI-Timestamp: %s\nAPI-Signature: %s\n%s',
    #                 api_key, api_timestamp, api_sign, body)
    # app.logger.info('Expected signature: %s', expected_sign)

    req = json.loads(body)
    app.logger.info("JSON-RPC Request:\n%s", json.dumps(req, indent=4))

    method = req.get("method", "")
    rpc_id = req.get("id", 0)

    handlers = dict(
        CREATE_GROUP=process_create_group,
        REMOVE_GROUP=process_remove_group,
        ADD_MEMBER=process_add_member,
        REMOVE_MEMBER=process_remove_member,
        UPDATE_MEMBER=process_update_member,
        NOTIFY_MEMBER=process_notify_member,
        NOTIFY_GROUP=process_notify_group
    )

    if method not in handlers:
        return json_error(req.get("id", rpc_id), -32601, "Unsupported method.")
    global pool
    conn = await pool.acquire()
    cursor = await conn.cursor()
    try:
        res = await handlers[method](cursor, req.get("params", {}))
        await conn.commit()
        return json_success(rpc_id, res if res else "")
    except Exception as e:
        app.logger.exception(e)
        await conn.rollback()
        return json_error(rpc_id, -32603, str(e))
    finally:
        pool.release(conn)


def json_error(id, code, message):
    return {"id": id, "jsonrpc": "2.0", "error": {"code": code, "message": message}}


def json_success(id, data):
    return {"id": id, "jsonrpc": "2.0", "result": data}


async def main():
    await hypercorn.asyncio.serve(app, hypercorn.Config())


if __name__ == "__main__":
    client.loop.run_until_complete(main())
