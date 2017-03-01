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

| HTTP Verb     | /{PubKeyFingerprint} | Body | Returns|
| ------------- |---------------------|------|--------|
| GET           | Get user information and passwords |  | `200`|
| POST          | Register a new user | publicKey | `201`|

### Password Manager

| HTTP Verb     | /{PubKeyFingerprint}/passwords | Body | Returns|
| ------------- |---------------------|------|--------|
| GET           | List all the user passwords |  | `200`|
| POST          | Create a new password associated to the user or update existing one | publicKey, tuple(domain, username, password), HMAC | `201`|

| HTTP Verb     | /{PubKeyFingerprint}/passwords/{passwordId} | Returns|
| ------------- |---------------------|--------|
| GET           | Get a specific password (`passwordId`) associated to the user | `200`|

| HTTP Verb     | /{PubKeyFingerprint}/passwords/retrievePassword | Body | Returns|
| ------------- |---------------------|-----------|--------|
| POST           | Retrieve a specific password associated to the user | publicKey, domain, username | `200` - Returns only the password |
