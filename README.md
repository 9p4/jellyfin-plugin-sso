# Jellyfin SSO Plugin

This plugin allows users to sign in through an SSO provider (such as Google, Facebook, or your own provider). This enables one-click signin.

https://github.com/sambhavsaggi/jellyfin-plugin-sso/raw/main/img/recording-resized.mp4

## Supported Protocols

- [OpenID](https://openid.net/what-is-openid/)
- [SAML](https://www.cloudflare.com/learning/access-management/what-is-saml/)

## Security

This is my first time writing C# so please take all of the code written here with a grain of salt. This program should be reasonably secure since it validates all information passed from the client with either a certificate or a secret internal state.

## Examples

### SAML

Example for adding a SAML configuration with the API using [curl](https://curl.se/):

`curl -v -X POST -H "Content-Type: application/json" -d '{"samlEndpoint": "https://keycloak.example.com/auth/realms/test/protocol/saml", "samlClientId": "jellyfin-saml", "samlCertificate": "Very long base64 encoded string here", "enabled": true, "enableAllFolders": true, "enabledFolders": ["folder1", "folder2"]}' "https://myjellyfin.example.com/sso/SAML/Add?api_key=API_KEY_HERE"`

Make sure that the JSON is the same as the configuration you would like.

The SAML provider must have the following configuration (I am using Keycloak, and I cannot speak for whatever you will see):

- Sign Documents on
- Sign Assertions off
- Client Signature Required off
- Redirect URI: [https://myjellyfin.example.com/sso/OID/p/clientid](https://myjellyfin.example.com/sso/OID/p/clientid)
- Base URL: [https://myjellyfin.example.com](https://myjellyfin.example.com)
- Master SAML processing URL: [https://myjellyfin.example.com/sso/saml/p/clientid](https://myjellyfin.example.com/sso/SAML/p/clientid)

Make sure that `clientid` is replaced with the actual client ID!

### OpenID

Example for adding an OpenID configuration with the API using [curl](https://curl.se/)

`curl -v -X POST -H "Content-Type: application/json" -d '{"oidEndpoint": "https://keycloak.example.com/auth/reapls/test", "oidClientId": "jellyfin-oid", "oidSecret": "short secret here", "enabled": true, "enableAllFolders": true, "enabledFolders": ["folder3", "folder4"]}' "https://myjellyfin.example.com/sso/OID/Add?api_key=API_KEY_HERE"`

The OpenID provider must have the following configuration (again, I am using Keycloak)

- Access Type: Confidential
- Standard Flow Enabled
- Redirect URI: [https://myjellyfin.example.com/sso/OID/r/clientid](https://myjellyfin.example.com/sso/OID/r/clientid)
- Base URL: [https://myjellyfin.example.com](https://myjellyfin.example.com)

Make sure that `clientid` is replaced with the actual client ID!

## Limitations

There is no GUI to sign in. You have to make it yourself! The buttons should redirect to something like this: [https://myjellyfin.example.com/sso/SAML/p/clientid](https://myjellyfin.example.com/sso/SAML/p/clientid) replacing `clientid` with the provider client ID and `SAML` with the auth scheme (either `SAML` or `OID`).

Furthermore, there is no functional admin page (yet). PRs for this are welcome. In the meantime, you have to interact with the API to add or remove configurations.

There is also no logout callback. Logging out of Jellyfin will log you out of Jellyfin only, instead of the SSO provider as well.
