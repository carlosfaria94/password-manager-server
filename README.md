# Password Manager Server

Implementation of a distributed password manager server with dependability guarantees.


## Implementation

A REST service API implemented using Spring Framework.

The data is persisted in memory using [H2](http://h2database.com/html/main.html).

## Running

```
mvn install
mvn clean spring-boot:run
```

## Endpoints

API Base URL: `http://localhost:8080`

### User

| HTTP Verb     | / | Body | Returns|
| ------------- |---------------------|------|--------|
| POST          | Register a new user | publicKey | `201`|

### Password Manager

| HTTP Verb     | /password | Body | Returns|
| ------------- |---------------------|------|--------|
| PUT          | Create a new password associated to the user or update existing one | publicKey, domain, username, password, digest(concat(domain,username,password)) | `201`|
| GET           | Retrieve a specific password associated to the user | publicKey, domain, username | `200` - Password, Digest |

All the messages are authenticated, fresh and non repudiable.
