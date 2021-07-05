# detribeGroupIds-app-sample

A sample App for detribes.

JSON-RPC definitions:

# Create Group:

```
{
    "id": 1,
    "jsonrpc": "2.0",
    "method": "CREATE_GROUP",
    "params": {
        "tribeGroupId": "1234...abcd",
        "tribeAddress": "0x1234...",
        "name": "NFT Discuss",
        "description": "Discuss how NFT works...",
        "address": "0xa1b2...",
        "expires": 1703213132,
        "username": "hello",
        "role": 0,
        "owner": true
    }
}
```

# Remove Group:

```
{
    "id": 1,
    "jsonrpc": "2.0",
    "method": "REMOVE_GROUP",
    "params": {
        "tribeGroupId": "1234...abcd",
        "tribeAddress": "0x1234...",
    }
}
```

# Add Member:

```
{
    "id": 1,
    "jsonrpc": "2.0",
    "method": "ADD_MEMBER",
    "params": {
        "tribeGroupId": "1234...abcd",
        "tribeAddress": "0x1234...",
        "address": "0xa1b2...",
        "username": "bob",
        "role": 0,
        "expires: 6000000000,
        "owner": false
    }
}
```

# Update Member:

```
{
    "id": 1,
    "jsonrpc": "2.0",
    "method": "UPDATE_MEMBER",
    "params": {
        "tribeGroupId": "1234...abcd",
        "tribeAddress": "0x1234...",
        "address": "0xa1b2...",
        "username": "bob",
        "role": 0,
        "expires: 1640995200,
        "owner": false
    }
}
```

# Remove Member:

```
{
    "id": 1,
    "jsonrpc": "2.0",
    "method": "REMOVE_MEMBER",
    "params": {
        "tribeGroupId": "1234...abcd",
        "tribeAddress": "0x1234...",
        "address": "0xa1b2...",
        "username": "bob"
    }
}
```

# Notify Member:

```
{
    "id": 1,
    "jsonrpc": "2.0",
    "method": "NOTIFY_MEMBER",
    "params": {
        "tribeGroupId": "1234...abcd",
        "tribeAddress": "0x1234...",
        "address": "0xa1b2...",
        "username": "bob",
        "message": "Hi bob, please note ..."
    }
}
```

# Notify Group:

```
{
    "id": 1,
    "jsonrpc": "2.0",
    "method": "NOTIFY_GROUP",
    "params": {
        "tribeGroupId": "1234...abcd",
        "tribeAddress": "0x1234...",
        "message": "Hi all, please note ..."
    }
}
```

# Database

Sample database schema for app:

```
CREATE TABLE channels (
    tribeGroupId VARCHAR(100) NOT NULL, -- tribeGroupId id from server
    tribeAddress VARCHAR(42) NOT NULL,    -- tribe address from server
    channelId BIGINT(20) NOT NULL,      -- the real telegram channel id
    name VARCHAR(100) NOT NULL,           -- channel name
    description VARCHAR(100) NOT NULL,    -- channel description
    CONSTRAINT UNI_CHANNEL_ID UNIQUE (channelId),
    PRIMARY KEY(tribeGroupId)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE members (
    id BIGINT AUTO_INCREMENT NOT NULL,
    tribeGroupId VARCHAR(100) NOT NULL, -- reference to channels.tribeGroupIdId
    address VARCHAR(42) NOT NULL,       -- the address of user
    username VARCHAR(100) NOT NULL,     -- the real telegram username in the channel
    userId BIGINT(20) NOT NULL,         -- telegram user id, it is not changed by username
    owner tinyint(1) not null default 0, -- indicate if member is owner of group
    role INT NOT NULL,                  -- the role of user
    expires BIGINT NOT NULL,            -- expires time in seconds
    metadata VARCHAR(100) NOT NULL,     -- extra metadata for user
    CONSTRAINT UNI_GROUP_USER UNIQUE (tribeGroupId, username, address),
    PRIMARY KEY(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
```
