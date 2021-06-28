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
