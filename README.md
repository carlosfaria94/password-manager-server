# Password Manager Server

Implementation of a distributed password manager server with dependability guarantees.


## Implementation

A REST service API implemented using Spring Framework.

The data is persisted in memory (using H2).

## Running

##### Set this environment variables

`FAULTS` - Number of faults that is designed to support

##### Install dependencies

```
mvn install
```

##### Starting the cluster according to the number of the faults to be supported

e.g. to support one fault

```
FAULTS=1 sh ./start.sh
```

##### Stop the cluster


```
FAULTS=1 sh ./stop.sh
```

##### To run only one instance

```
SERVER_PORT=3001 mvn spring-boot:run -Dmaven.test.skip
```

## Endpoints

API Base URL: `http://localhost:8080`

### User

| HTTP Verb     | / | Body | Returns|
|:-------------:|:---------------------|------|:--------|
| POST          | Register a new user | publicKey, signature | The new user with `201` status code|

### Password Manager

| HTTP Verb     | /password | Body | Returns|
|:-------------:|:---------------------|------|:--------|
| PUT          | Create a new password or update existing one | publicKey, domain, username, password, pwdSignature, timestamp, nonce, reqSignature | The new password or the updated one with `201` status code |

| HTTP Verb     | /retrievePassword | Body | Returns|
|:-------------:|:---------------------|------|:--------|
| POST           | Retrieve a specific password associated to the user (publicKey) | publicKey, domain, username | The password (domain, password, username, pwdSignature, timestamp, nonce, reqSignature) with `200` status code |


All the messages are authenticated, fresh and non repudiable.
