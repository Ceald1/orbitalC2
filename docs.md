# API

## User Routes

### `/user/login`
#### POST
example json:
```json
{
    "username":"admin",
    "password":"pass"
}
```
outputs a JWT for interacting with the database routes. Example output:
```json
{
    "message":"my jwt"
}
```

## Database routes
All database routes require an Authentication header `Authorization: <JWT>`

### `/db/agent` and `/db/agent/`
#### GET
returns an array of strings. Example output:
```json
{
    "message":[
        "agent1",
        "agent2"
    ]
}
```
### `/db/agent/create`
#### GET
create an agent, returns new agent ID as a string.
```json
{
    "message": "agent id"
}
```

### `/db/clear`
#### GET
clear the entire database, response:
```json
{
    "message": 200
}
```

### `/db/delete`
#### POST
Example POST JSON:
```json
{
    "id":"agent id"
}
```
response:
```json
{
    "message": 200
}
```
Will display error if error in JSON message.


## C2 endpoints
C2 endpoints require admin JWT just like DB endpoints.

### `/c2/command/send`
#### POST
Send commands for agents to run. Example JSON:
```JSON
{
    "agent":"agent id",
    "command": "command",
    "directory": "directory to run command"
}
```
Returns status code or error
```json
{
    "message": 200
}
```
