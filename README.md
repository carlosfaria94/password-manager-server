# Password Manager Server

Implementation of a distributed password manager server with dependability guarantees.


## Implementation

This is a REST service API, implemented using Spring Framework.

The data is persisted in memory using [H2](http://h2database.com/html/main.html).

## Executing

```
mvn install
mvn clean spring-boot:run
```

## Endpoints

API Base URL: `http://localhost:8080`

| HTTP Verb     | /{userId}/passwords | Returns|
| ------------- |---------------------|--------|
| GET           | List all the user passwords | `200`|
| POST          | Create a new password associated to the user | `201`|

| HTTP Verb     | /{userId}/passwords/{passwordId} | Returns|
| ------------- |---------------------|--------|
| GET           | Get a specific password (`passwordId`) associated to the user | `200`|