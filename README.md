# kong-go-plugin-jwt-kc

A Kong Go plugin to validate access tokens issued by Keycloak. This plugins is inspired by the
Lua-based [kong-plugin-jwt-keycloak](https://github.com/telekom-digioss/kong-plugin-jwt-keycloak). There are, however,
some differences.

## Features

- Validates signed JWT access tokens
- Verifies the token signature using the public key retrieved from the [
  `.well-known` endpoint](https://datatracker.ietf.org/doc/html/rfc5785)
- Supports multiple trusted issuers
- Supports multiple public keys per issuer (e.g., for key rotation) including caching
- Authorization based on the token's claims
    - `scope`
    - `realm_access`
    - `resource_access`
- Consumer matching based on the token
- Supports multiple signing algorithms (RS*, ES*)

## Configuration

### Global plugin configuration

The plugin's global behavior can be configured using the following properties:

| Property                                        | Description                                      | Default    |
|-------------------------------------------------|--------------------------------------------------|------------|
| KONG_PLUGIN_CONFIG_JWT_GO_JWKS_CACHE_EXPIRATION | The expiration time of the JWKS cache in seconds | `6 * 3600` |
| KONG_PLUGIN_CONFIG_GO_JWT_KC_SKIP_TLS_VERIFY    | Skip the verification of the TLS certificates    | `false`    |

### Instance-specific plugin configuration

A plugin instance can be configured using the following properties:

| Property                        | Description                                                                                          | Default                                 |
|---------------------------------|------------------------------------------------------------------------------------------------------|-----------------------------------------|
| uri_param_names                 | The names of the query parameters that may contain the access token                                  | `""`                                    |
| cookie_names                    | The names of the cookies that may contain the access token                                           | `""`                                    |
| header_names                    | The names of the headers that may contain the access token                                           | `"authorization"`                       |
| claims_to_verify                | The claims to verify                                                                                 | `"exp"`                                 |
| anonymous                       | If a kong consumer uuid is set, the plugin will use this consumer for requests without a valid token | `""`                                    |
| run_on_preflight                | If the plugin should run on preflight requests                                                       | `false`                                 |
| maximum_expiration              | The maximum remaining expiration time of the token in seconds                                        | `0`                                     |
| algorithms                      | The supported signing algorithms                                                                     | `"HS256,ES256"`                         |
| allowed_iss                     | The allowed issuers                                                                                  | `""`                                    |
| well_known_template             | The template for the well-known endpoint                                                             | `"%s/.well-known/openid-configuration"` |
| scopes                          | The required scopes                                                                                  | `""`                                    |
| roles                           | The required roles                                                                                   | `""`                                    |
| realm_roles                     | The required realm roles                                                                             | `""`                                    |
| client_roles                    | The required client roles                                                                            | `""`                                    |
| consumer_match                  | Should the plugin try to match the consumer based on the token                                       | `false`                                 |
| consumer_match_claim            | The claim to use for the consumer matching                                                           | `"azp"`                                 |
| consumer_match_ignore_not_found | Ignore consumer not found errors                                                                     | `false`                                 |
