# Jellyfin SSO Plugin

This plugin allows users to sign in through an SSO provider (such as Google, Facebook, or your own provider). This enables one-click signin.

https://user-images.githubusercontent.com/17993169/149681516-f93b43f5-fa5c-4c1f-a909-e5414878a864.mp4

## Current State:

This is 100% alpha software! PRs are welcome to improve the code.

There is NO admin configuration! You must use the API to configure the program!

**This is for Jellyfin 10.8**

**This README reflects the __main__ branch! Switch tags to view version-specific documentation!**

## Tested Providers

- Google OpenID: Works, but usernames are all numeric
- Keycloak OpenID and SAML: Works

## Supported Protocols

- [OpenID](https://openid.net/what-is-openid/)
- [SAML](https://www.cloudflare.com/learning/access-management/what-is-saml/)

## Security

This is my first time writing C# so please take all of the code written here with a grain of salt. This program should be reasonably secure since it validates all information passed from the client with either a certificate or a secret internal state.

## Installing

Add the package repo [https://repo.saggis.com/jellyfin/manifest.json](https://repo.saggis.com/jellyfin/manifest.json) to your Jellyfin configuration. Then, install the package!

## Building

This is built with .NET 6.0. Build with `dotnet publish .` for the debug release in the `SSO-Auth` directory. Copy over the `IdentityModel.OidcClient.dll`, the `IdentityModel.dll` and the `SSO-Auth.dll` files in the `/bin/Debug/net6.0/publish` directory to a new folder in your Jellyfin configuration: `config/plugins/sso`.

## Releasing

This plugin uses [JPRM](https://github.com/oddstr13/jellyfin-plugin-repository-manager) to build the plugin. Refer to the documentation there to install JPRM.

Build the zipped plugin with `jprm --verbosity=debug plugin build .`.

## Roadmap

- [ ] Admin page
- [ ] Automated tests
- [x] Add role/claims support
- [ ] Use canonical usernames instead of preferred usernames

## Examples

### SAML

Example for adding a SAML configuration with the API using [curl](https://curl.se/):

`curl -v -X POST -H "Content-Type: application/json" -d '{"samlEndpoint": "https://keycloak.example.com/realms/test/protocol/saml", "samlClientId": "jellyfin-saml", "samlCertificate": "Very long base64 encoded string here", "enabled": true, "enableAuthorization": true, "enableAllFolders": true, "enabledFolders": ["folder1", "folder2"], "adminRoles": [], "roles": [], "enableFolderRoles": false, "folderRoleMapping": [{"role": "Movies", "folders": ["Movie1", "Movie2"]}]}' "https://myjellyfin.example.com/sso/SAML/Add?api_key=API_KEY_HERE"`

Make sure that the JSON is the same as the configuration you would like.

The SAML provider must have the following configuration (I am using Keycloak, and I cannot speak for whatever you will see):

- Sign Documents on
- Sign Assertions off
- Client Signature Required off
- Redirect URI: [https://myjellyfin.example.com/sso/SAML/p/clientid](https://myjellyfin.example.com/sso/OID/p/clientid)
- Base URL: [https://myjellyfin.example.com](https://myjellyfin.example.com)
- Master SAML processing URL: [https://myjellyfin.example.com/sso/SAML/p/clientid](https://myjellyfin.example.com/sso/SAML/p/clientid)

Make sure that `clientid` is replaced with the actual client ID!

### OpenID

Example for adding an OpenID configuration with the API using [curl](https://curl.se/)

`curl -v -X POST -H "Content-Type: application/json" -d '{"oidEndpoint": "https://keycloak.example.com/realms/test", "oidClientId": "jellyfin-oid", "oidSecret": "short secret here", "enabled": true, "enableAllFolders": true, "enabledFolders": ["folder3", "folder4"], "enableAuthorization": true, "adminRoles": [], "roles": [], "enableFolderRoles": false, roleClaim: "realm_roles", "folderRoleMapping": [{"role": "Movies", "folders": ["Movie1", "Movie2"]}]}' "https://myjellyfin.example.com/sso/OID/Add?api_key=API_KEY_HERE"`

The OpenID provider must have the following configuration (again, I am using Keycloak)

- Access Type: Confidential
- Standard Flow Enabled
- Redirect URI: [https://myjellyfin.example.com/sso/OID/r/clientid](https://myjellyfin.example.com/sso/OID/r/clientid)
- Base URL: [https://myjellyfin.example.com](https://myjellyfin.example.com)

Make sure that `clientid` is replaced with the actual client ID!

## API Endpoints

The API is all done from a base URL of `/sso/`

### SAML

#### Flow

- POST `SAML/p/clientid`: This is the SAML POST endpoint. It accepts a form response from the SAML provider and returns HTML and JavaScript for the client to login.
- GET `SAML/p/clientid`: This is the SAML initiator: it will begin the authorization flow for SAML with a given client ID.
- POST `SAML/Auth`: This is the SAML client-side API: the HTML and JavaScript client will call this endpoint to receive Jellyfin credentials. Post format is in JSON with the following keys:
  - `deviceId`: string. Device ID.
  - `deviceName`: string. Device name.
  - `appName`: string. App name.
  - `appVersion`: string. App version.
  - `data`: string. The signed SAML XML request. Used to verify a request.
  - `provider`: string. The current SAML client ID.

#### Configuration

These all require authorization. Append an API key to the end of the request: `curl "http://myjellyfin.example.com/sso/SAML/Get?api_key=API_KEY_HERE"`

- POST `SAML/Add`: This adds a configuration for SAML. It accepts JSON with the following keys and format:
  - `samlEndpoint`: string. The SAML endpoint.
  - `samlClientId`: string. The SAML client ID.
  - `samlCertificate`: string. The base64 encoded SAML certificate.
  - `enabled`: boolean. Determines if the provider is enabled or not.
  - `enableAuthorization`: boolean: Determines if the plugin sets permissions for the user. If false, the user will start with no permissions and an administrator will add permissions. The permissions of existing users will not be rewritten on subsequent logins.
  - `enableAllFolders`: boolean. Determines if the client logging in is allowed access to all folders.
  - `enabledFolders`: array of strings. If `enableAllFolders` is set to false, then this will be used to determine what folders the users who log in through this provider are allowed to use.
  - `roles`: array of strings. This validates the SAML response against the `Role` attribute. If a user has any of these roles, then the user is authenticated. Leave blank to disable role checking.
  - `adminRoles`: array of strings. This uses SAML response's `Role` attributes. If a user has any of these roles, then the user is an admin. Leave blank to disable (default is to not enable admin permissions).
  - `enableFolderRoles`: boolean. Determines if role-based folder access should be used.
  - `folderRoleMapping`: object in the format "role": string and "folders": array of strings. The user with this role will have access to the following folders if `enableFolderRoles` is enabled. To get the IDs of the folders, GET the `/Library/MediaFolders` URL with an API key. Look for the `Id` attribute.
- GET `SAML/Del/clientId`: This removes a configuration for SAML for a given client ID.
- GET `SAML/Get`: Lists the configurations currently available.


### OpenID

#### Flow

- GET `OID/r/clientId`: This is the OpenID callback path. This will return HTML and JavaScript for the client to login.
- GET `OID/p/clientId`: This is the OpenID initiator: it will begin the authorization flow for OpenID with a given client ID.
- POST `OID/Auth`: This is the OpenID client-side API: the HTML and JavaScript client will call this endpoint to receive Jellyfin credentials. Post format is in JSON with the following keys:
  - `deviceId`: string. Device ID.
  - `deviceName`: string. Device name.
  - `appName`: string. App name.
  - `appVersion`: string. App version.
  - `data`: string. The OpenID state. Used to verify a request.
  - `provider`: string. The current OpenID client ID.

#### Configuration

These all require authorization. Append an API key to the end of the request: `curl "http://myjellyfin.example.com/sso/OID/Get?api_key=9c6e5fae4ae145669e6b7a3942f813b7"`

- POST `OID/Add`: This adds a configuration for OpenID. It accepts JSON with the following keys and format:
  - `oidEndpoint`: string. The OpenID endpoint. Must have a `.well-known` path available.
  - `oidClientId`: string. The OpenID client ID.
  - `oidSecret`: string. The OpenID secret.
  - `enabled`: boolean. Determines if the provider is enabled or not.
  - `enableAuthorization`: boolean: Determines if the plugin sets permissions for the user. If false, the user will start with no permissions and an administrator will add permissions. The permissions of existing users will not be rewritten on subsequent logins.
  - `enableAllFolders`: boolean. Determines if the client logging in is allowed access to all folders.
  - `enabledFolders`: array of strings. If `enableAllFolders` is set to false, then this will be used to determine what folders the users who log in through this provider are allowed to use.
  - `roles`: array of strings. This validates the OpenID response against the claim set in `roleClaim`. If a user has any of these roles, then the user is authenticated. Leave blank to disable role checking. This currently only works for Keycloak (to my knowledge).
  - `adminRoles`: array of strings. This uses the OpenID response against the claim set in `roleClaim`. If a user has any of these roles, then the user is an admin. Leave blank to disable (default is to not enable admin permissions).
  - `enableFolderRoles`: boolean. Determines if role-based folder access should be used.
  - `folderRoleMapping`: object in the format "role": string and "folders": array of strings. The user with this role will have access to the following folders if `enableFolderRoles` is enabled. To get the IDs of the folders, GET the `/Library/MediaFolders` URL with an API key. Look for the `Id` attribute.
  - `roleClaim`: string. This is the value in the OpenID response to check for roles. For Keycloak, it is `realm_roles` by default.
- GET `OID/Del/clientId`: This removes a configuration for OpenID for a given client ID.
- GET `OID/Get`: Lists the configurations currently available.
- GET `OID/States`: Lists currently active OpenID flows in progress.

## Limitations

There is no GUI to sign in. You have to make it yourself! The buttons should redirect to something like this: [https://myjellyfin.example.com/sso/SAML/p/clientid](https://myjellyfin.example.com/sso/SAML/p/clientid) replacing `clientid` with the provider client ID and `SAML` with the auth scheme (either `SAML` or `OID`).

Furthermore, there is no functional admin page (yet). PRs for this are welcome. In the meantime, you have to interact with the API to add or remove configurations.

There is also no logout callback. Logging out of Jellyfin will log you out of Jellyfin only, instead of the SSO provider as well.

~~This only supports Jellyfin on it's own domain (for now). This is because I'm using string concatenation for generating some URLs. A PR is welcome to patch this.~~ Fixed in [PR #1](https://github.com/9p4/jellyfin-plugin-sso/pull/1).

**This only works on the web UI**. The user must open the Jellyfin web UI BEFORE using the SSO program to populate some values in the localStorage.

## Credits and Thanks

Much thanks to the [Jellyfin LDAP plugin](https://github.com/jellyfin/jellyfin-plugin-ldapauth) for offering a base for me to start on my plugin.

I use the [AspNet SAML](https://github.com/jitbit/AspNetSaml/) library for the SAML side of things (patched to work with Base64 on non-Windows machines).

I use the [IdentityModel OIDC Client](https://github.com/IdentityModel/IdentityModel.OidcClient/) library for the OpenID side of things.

Thanks to these projects, without which I would have been pulling my hair out implementing these protocols from scratch.
