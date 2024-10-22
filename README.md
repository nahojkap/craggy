# craggy

Craggy is a Roughtime secure time synchronization client implementation in C.  It draws both code and inspiration from the Google C++ client implementation. 

![CMake Build](https://github.com/nahojkap/craggy/workflows/CMake/badge.svg)

### Dependencies

Craggy requires two cryptographic operations to work, ED 25519 signature validation and SHA512.

Current build can be configured to use either OpenSSL or the ED 25519 implementation from https://github.com/orlp/ed25519 (which also provides SHA512).

To configure the crypto provider, use '-DCRAGGY_WITH_OPENSSL_BINDINGS=ON' or '-DCRAGGY_WITH_ORLP_ED25519_BINDINGS=ON' respectively.

When using the OpenSSL, Craggy will link to the platform provided OpenSSL libraries, while when using the ORLP/ED25519 implementation, it will download and compile the sources for that as part of the build. 

### Getting started

The following will build craggy static library with ORLP/ED25519 bindings, the craggy-cli command line client (located in the build/cli folder) and the craggy-test runner (located in the test folder)

```shell script
bash$ git clone https://github.com/nahojkap/craggy.git
...
bash$ cd craggy
bash$ cmake -E make_directory ./build
bash$ cmake -S . -B ./build/ -DCRAGGY_WITH_ORLP_ED25519_BINDINGS=ON
...
bash$ cd build
bash$ make
...
bash$ make test
..
bash$
```

### API

The API of Craggy is defined in the [CraggyClient.h](library/CraggyClient.h) header file.  

A UDP transport implementation is available (compiled in by default) and is defined in [CraggyTransport.h](library/CraggyTransport.h) 

#### Generating Nonces

```c
/** Generates a new nonce value, placing it in the nonce specified.
 * 
 * @param result Result of the nonce creation
 * @param nonce Nonce to place the generated value in
 * @return True if successful, otherwise false and {@link result} will indicate the error
 */
bool craggy_generateNonce(CraggyResult *result, craggy_rough_time_nonce_t nonce);
``` 

#### Creating Requests
```c
/** Creates a new Roughtime request message containing the specified nonce.
 *
 * @param nonce The nonce to include in the request
 * @param requestBuf Buffer for the request
 * @param requestBufLen Buffer length
 * @return True if the request creation was successful, otherwise false
 */
bool craggy_createRequest(craggy_rough_time_nonce_t nonce, craggy_rough_time_request_t requestBuf);
``` 

#### Processing Responses

```c
/** Processes a response from the server, verifying the necessary signatures and extracting the time and radius if successful.
 *
 * @param nonce The nonce originally used for creating the request
 * @param rootPublicKey Root public key of the server in question
 * @param responseBuf Response to be processed
 * @param responseBufLen Size of the response to be processed
 * @param result Result of response processing
 * @param time Time reported by the server
 * @param radius Radius reported by the server
 * @return True if the request creation was successful, otherwise false and {@link result} will signal the error
 */
bool craggy_processResponse(craggy_rough_time_nonce_t nonce, craggy_rough_time_public_key_t rootPublicKey, craggy_rough_time_response_t *responseBuf, size_t responseBufLen, CraggyResult *result, craggy_rough_time_t *time, craggy_rough_time_radius_t *radius);
``` 

#### Sending/Receiving a Request/Response

```shell script
/** Send a Roughtime request to the server and return the response received.
 *
 * @param address The host/port to send the paylaod to.  In the form of <hostname> or <hostname:port>.  If port is omitted, the transports default value will be used.
 * @param requestBuf Buffer containing the request to send.
 * @param result Result of transport operation
 * @param responseBuf Buffer used for response
 * @param responseBufLen Size of the response buffer.  If a response is successfully received, the corresponding size of the response is signalled here too.
 * @return True if the request is successful, otherwise false (and outResult will indicate the error)
 */
bool craggy_makeRequest(const char *address, const craggy_rough_time_request_t requestBuf, CraggyResult *result, craggy_rough_time_response_t *responseBuf, size_t *responseBufLen);
```

### Command line 

The command line for the craggy-cli requires the below parameters.  If nonce is not specified on the command line, a random one will be generated.

```shell script
usage: craggy-cli -h <hostname:port> -k <base64 encoded public key of server> (-n <64-bit base64 encoded nonce>)
```

#### Example 

```shell script
bash$ cli/craggy -h roughtime.cloudflare.com:2002 -k gD63hSj3ScS+wuOeGrubXlq35N1c5Lby/S+T7MNTjxo=
Received reply in 24291μs.
Current time is 1602858064681145μs from the epoch, ±1000000μs 
System clock differs from that estimate by 110μs.
```