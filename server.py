import json

from telethon.sync import TelegramClient
from telethon.tl.functions.channels import (
    CreateChannelRequest,
    InviteToChannelRequest,
    DeleteChannelRequest,
)
import aiomysql

from quart import Quart, request

import hypercorn
from logging.config import dictConfig

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
    select id, tribeGroupId, address, username, role, expires, metadata, owner from members where tribeGroupId=%s and username=%s and address=%s
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
    await cursor.execute(remove_channel_sql, tribe_group_id)


async def add_member(
    cursor, tribe_group_id, address, username, expires, role=0, owner=False, metadata=""
):
    insert_member_sql = """
    insert into members (tribeGroupId, address, username, role, expires, owner, metadata) values (%s, %s, %s, %s, %s, %s, %s)
    """
    await cursor.execute(
        insert_member_sql,
        (
            tribe_group_id,
            address,
            username,
            role,
            expires,
            owner,
            metadata,
        ),
    )


async def update_member(
    cursor, tribe_group_id, address, username, expires, role, owner, metadata
):
    update_member_sql = """
    update members set expires=%s, role=%s,owner=%s,metadata=%s where tribeGroupId=%s and address=%s and username=%s
    """
    await cursor.exeucute(
        update_member_sql,
        (expires, role, owner, metadata, tribe_group_id, address, username),
    )


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
    req = await client(CreateChannelRequest(name, description))
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
    await add_member(cursor, tribe_group_id, address, username, 0, 0, True)
    return dict(channel_id=channel_id)


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
    await close_db()
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
        # REMOVE_GROUP=process_remove_group,
        # ADD_MEMBER=process_add_member,
        # REMOVE_MEMBER=process_remove_member,
        # UPDATE_MEMBER=process_update_member,
        # NOTIFY_MEMBER=process_notify_member
    )

    if method not in handlers:
        return json_error(req.get("id", rpc_id), -32601, "Unsupported method.")
    global pool
    conn = await pool.acquire()
    cursor = await conn.cursor()
    try:
        res = await handlers[method](cursor, req.get("params", {}))
        await conn.commit()
        if res:
            return json_success(rpc_id, json.dumps(res))
        else:
            return json_success(rpc_id, "")
    except Exception as e:
        app.logger.exception(e)
        await conn.rollback()
        return json_error(rpc_id, -32603, str(e))


def json_error(id, code, message):
    return {"id": id, "jsonrpc": "2.0", "error": {"code": code, "message": message}}


def json_success(id, data):
    return {"id": id, "jsonrpc": "2.0", "result": data}


async def main():
    await hypercorn.asyncio.serve(app, hypercorn.Config())


if __name__ == "__main__":
    client.loop.run_until_complete(main())
