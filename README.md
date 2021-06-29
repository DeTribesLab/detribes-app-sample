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
        "tribeGroupId": "1234...abcd"
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
        "tribeGroupId": "1234...abcd"
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
        "member": "0x...member...address...",
        "username": "hello",
        "role": 0
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
        "member": "0x...member...address...",
        "username": "hello",
        "role": 0
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
        "member": "0x...member...address..."
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
        "member": "0x...member...address...",
        "username": "hello",
        "message": "please note ..."
    }
}
```

# Database

Sample database schema for app:

```
CREATE TABLE channels (
    tribeGroupIdId VARCHAR(100) NOT NULL, -- tribeGroupId id from server
    channelId VARCHAR(100) NOT NULL,      -- the real telegram channel id
    name VARCHAR(100) NOT NULL,           -- channel name
    description VARCHAR(100) NOT NULL,    -- extra metadata for channel
    CONSTRAINT UNI_CHANNEL_ID UNIQUE (channelId),
    PRIMARY KEY(tribeGroupIdId)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE members (
    id BIGINT AUTO_INCREMENT NOT NULL,
    tribeGroupIdId VARCHAR(100) NOT NULL, -- reference to channels.tribeGroupIdId
    userId VARCHAR(100) NOT NULL,         -- the real telegram username in the channel
    role INT NOT NULL,                    -- the role of user
    description VARCHAR(100) NOT NULL,    -- extra metadata for user
    CONSTRAINT UNI_tribeGroupId_USER UNIQUE (tribeGroupIdId, userId),
    PRIMARY KEY(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
```
