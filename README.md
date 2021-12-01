# Hitachi FAPI Implementation for Java

Reference Implementation of Financial-grade API 1.0(FAPI 1.0) Client Application and Resource Server following [Financial-grade API Security Profile 1.0 - Part 2: Advanced](https://openid.net/specs/openid-financial-api-part-2-1_0.html) 

## Specs of Client Application

- TLS
- JSON Web Key ([RFC7517](https://datatracker.ietf.org/doc/html/rfc7517))
- Support Obtaining Authorization Server Metadata ([Chapter 3 of RFC8414](https://datatracker.ietf.org/doc/html/rfc8414#section-3))
- Hybrid Flow ([Section 3.3 of OpenID Connect Core 1.0 incorporating errata set 1](https://openid.net/specs/openid-connect-core-1_0.html#HybridFlowAuth))
- [OAuth 2.0 Form Post Response Mode](https://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html)
- Proof Key for Code Exchange by OAuth Public Clients ([RFC7636](https://tools.ietf.org/html/rfc7636))
- Support Passing a Request Object by Value ([Section 6.1 of OpenID Connect Core 1.0 incorporating errata set 1](https://openid.net/specs/openid-connect-core-1_0.html#RequestObject))
- Support signature algorithm
    - PS256
    - ES256
- Support key encryption algorithm
    - RSA-OAEP
    - RSA-OAEP-256
- ID Token as Detached Signature
- Client Authentication
    - private_key_jwt ([Chapter 9 of OpenID Connect Core 1.0 incorporating errata set 1](https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication))
    - tls_client_auth ([Section 2.1 of RFC8705](https://datatracker.ietf.org/doc/html/rfc8705#section-2.1))
- OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access Tokens ([RFC8705](https://tools.ietf.org/html/rfc8705))
- Refresh Request ([Chapter 12 of of OpenID Connect Core 1.0 incorporating errata set 1](https://openid.net/specs/openid-connect-core-1_0.html#RefreshTokens))
- OAuth 2.0 Token Revocation ([RFC7009](https://datatracker.ietf.org/doc/html/rfc7009))

## Specs of Resource Server

- TLS
- Client Authentication
    - tls_client_auth ([Section 2.1 of RFC8705](https://datatracker.ietf.org/doc/html/rfc8705#section-2.1))
- OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access Tokens ([RFC8705](https://tools.ietf.org/html/rfc8705))
- Token Introspection ([RFC7662](https://datatracker.ietf.org/doc/html/rfc7662))

## Requirements

- Java 11
- Apache Maven 3.6


## How to run client and resource server

- client
    ```sh
    $ cd client
    $ mvn spring-boot:run
    ```

- resource server
    ```sh
    $ cd server
    $ mvn spring-boot:run
    ```

## Precautions

- This code is provided "as is" without warranty of any kind.
- We don't take responsibility for any damage by using this sample source code.

## License

- [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0)