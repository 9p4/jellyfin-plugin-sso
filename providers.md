# Provider Specific Configuration

This plugin has been tested to work against various providers, though not all providers provide support for all of this plugins' features.

## TOC / Tested Providers:

This section is broken into providers that support Role-Based Access Control (RBAC), and those that do not

### Providers that support RBAC

- ✅ [Authelia](#authelia)
- ✅ [Authentik](#authentik)
- [✅ Keycloak](#keycloak-oidc)
  - Both [OIDC](#keycloak-oidc) & [SAML](#keycloak-saml)

### No RBAC Support

- ✅ Google OIDC
  - ❗ Usernames are numeric

## General Options, when RBAC is supported

For any provider that supports RBAC, we can configure it as we see fit:

```yaml
Enabled: true
EnableAuthorization: true
EnableAllFolders: true
EnabledFolders: []
Roles: ["jellyfin_user"]
AdminRoles: ["jellyfin_admin"]
EnableFolderRoles: false
FolderRoleMapping: []
```

## Authelia

Authelia is simple to configure, and RBAC is straightfoward

### Authelia's Config

Below is the `identity_providers` section of an authelia config:

```yaml
identity_providers:
  oidc:
    # hmac secret and private key given by env variables
    clients:
      - id: jellyfin
        description: My media server
        # Client secret should be randomly generated
        secret: <redacted>
        authorization_policy: one_factor
        redirect_uris:
          - https://jellyfin.example.com/sso/OID/r/authelia
```

### Jellyfin's Config

On the end of `jellyfin`, we need to configure an authelia provider as follows:

In order to test group membership, we need to request authelia's OIDC scope `groups`,
which we will use to check user roles.

```yaml
authelia:
  OidEndpoint: https://authelia.example.com/.well-known/openid-configuration/
  OidClientId: jellyfin
  OidSecret: <redacted>
  RoleClaim: groups
  OidScopes: ["groups"]
```

## Authentik

To begin with, we must set up an OIDC Provider + Application in Authentik. See the official docs for a walkthrough of this.

### Authentik's Config

Authentik supports RBAC, but is slightly more complicated to configure than authelia, as we need to configure a custom scope binding to include in the OIDC response.

To do this, we:

- create a **Custom Property Mapping**

  ![image](img/authentik-config-01.jpg)

- Create a **Scope Mapping**

  ![image](img/authentik-config-02.jpg)

- Assign the following attributes:

  ![image](img/authentik-config-03.jpg)

  ```yaml
  # A nice, human readable name
  name: Group Membership
  # The name of the scope a client must request to get access to a user's groups
  Scope Name: groups
  # A description of what is being requested to show to a user
  Description: See Which Groups you belong to
  ```

- For the **Expression** field, use the following code:
  ```python
  return [group.name for group in user.ak_groups.all()]
  ```

Now we can add this property mapping to our Authentik's jellyfin OAuth provider:

- Navigate to `Applications/providers`

  ![image](img/authentik-config-04.jpg)

- Edit / Update your Jellyfin OAuth provider
- Under **"Advanced Protocol Settings"**, add the **Group Membership** Scope

  ![image](img/authentik-config-05.jpg)

### Jellyfin's Config

On the end of `jellyfin`, we need to configure an authelia provider as follows:

In order to test group membership, we need to request authelia's OIDC scope `groups`,
which we will use to check user roles.

```yaml
authelia:
  OidEndpoint: https://authentik.example.com/application/o/jellyfin/.well-known/openid-configuration/
  OidClientId: <same-as-in-authentik>
  OidSecret: <redacted>
  RoleClaim: groups
  OidScopes: ["groups"]
```

## Keycloak OIDC

### Keycloaks Config (TODO)

### Jellyfin's Config

On the end of `jellyfin`, we need to configure a keycloak provider as follows:

```yaml
authelia:
  OidEndpoint: https://keycloak.example.com/realms/test/
  OidClientId: jellyfin-oid
  OidSecret: <redacted>
  RoleClaim: realm_access.roles
```

## Keycloak SAML

**(TODO)**

### Keycloaks Config (TODO)

### Jellyfin's Config (TODO)
