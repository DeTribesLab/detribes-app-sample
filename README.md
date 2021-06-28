# detribes-app-sample

A sample App for detribes.

JSON-RPC definitions:

# Create Group:

```
{
    "id": 1,
    "jsonrpc": "2.0",
    "method": "CREATE_GROUP",
    "params": {
        "tribe": "0x...tribe...address..."
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
        "tribe": "0x...tribe...address..."
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
        "tribe": "0x...tribe...address...",
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
        "tribe": "0x...tribe...address...",
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
        "tribe": "0x...tribe...address...",
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
        "tribe": "0x...tribe...address...",
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
    tribeId VARCHAR(100) NOT NULL,     -- tribe id from server
    channelId VARCHAR(100) NOT NULL,   -- the real telegram channel id
    description VARCHAR(100) NOT NULL, -- extra metadata for channel
    CONSTRAINT UNI_CHANNEL_ID UNIQUE (channelId),
    PRIMARY KEY(tribeId)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE members (
    id BIGINT AUTO_INCREMENT NOT NULL,
    tribeId VARCHAR(100) NOT NULL,     -- reference to channels.tribeId
    userId VARCHAR(100) NOT NULL,      -- the real telegram username in the channel
    role INT NOT NULL,                 -- the role of user
    description VARCHAR(100) NOT NULL, -- extra metadata for user
    CONSTRAINT UNI_TRIBE_USER UNIQUE (tribeId, userId),
    PRIMARY KEY(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
```
