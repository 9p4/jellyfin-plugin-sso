using System;
using System.Collections.Generic;
using System.Xml.Serialization;

namespace Jellyfin.Plugin.SSO_Auth.Config;

/// <summary>
/// Plugin Configuration.
/// </summary>
public class PluginConfiguration : MediaBrowser.Model.Plugins.BasePluginConfiguration
{
    /// <summary>
    /// Initializes a new instance of the <see cref="PluginConfiguration"/> class.
    /// </summary>
    public PluginConfiguration()
    {
        SamlConfigs = new SerializableDictionary<string, SamlConfig>();
        OidConfigs = new SerializableDictionary<string, OidConfig>();
    }

    /// <summary>
    /// Gets or sets the SAML configurations available.
    /// </summary>
    [XmlElement("SamlConfigs")]
    public SerializableDictionary<string, SamlConfig> SamlConfigs { get; set; }

    /// <summary>
    /// Gets or sets the OpenID configurations available.
    /// </summary>
    [XmlElement("OidConfigs")]
    public SerializableDictionary<string, OidConfig> OidConfigs { get; set; }
}

/// <summary>
/// The configuration required for a SAML flow.
/// </summary>
[XmlRoot("PluginConfiguration")]
public class SamlConfig
{
    private SerializableDictionary<string, Guid> _canonicalLinks;

    /// <summary>
    /// Gets or sets the SAML information endpoint.
    /// </summary>
    public string SamlEndpoint { get; set; }

    /// <summary>
    /// Gets or sets the SAML provider's client ID.
    /// </summary>
    public string SamlClientId { get; set; }

    /// <summary>
    /// Gets or sets the SAML public key.
    /// </summary>
    public string SamlCertificate { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether the provider is enabled.
    /// </summary>
    public bool Enabled { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether RBAC is enabled.
    /// </summary>
    public bool EnableAuthorization { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether all folders are allowed by default.
    /// </summary>
    public bool EnableAllFolders { get; set; }

    /// <summary>
    /// Gets or sets what folders should users have access to by default.
    /// </summary>
    public string[] EnabledFolders { get; set; }

    /// <summary>
    /// Gets or sets the roles that are checked to determine whether the user is an administrator.
    /// </summary>
    public string[] AdminRoles { get; set; }

    /// <summary>
    /// Gets or sets what roles are checked to determine whether the user is allowed to use Jellyfin.
    /// </summary>
    public string[] Roles { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether RBAC is used to manage folder access.
    /// </summary>
    public bool EnableFolderRoles { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether RBAC is used to manage Live TV access.
    /// </summary>
    public bool EnableLiveTvRoles { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether Live TV is enabled by default.
    /// </summary>
    public bool EnableLiveTv { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether Live TV is allowed to be managed by default.
    /// </summary>
    public bool EnableLiveTvManagement { get; set; }

    /// <summary>
    /// Gets or sets the roles that are checked to determine whether the user is allowed to view Live TV.
    /// </summary>
    public string[] LiveTvRoles { get; set; }

    /// <summary>
    /// Gets or sets the roles that are checked to determine whether the user is allowed to manage Live TV.
    /// </summary>
    public string[] LiveTvManagementRoles { get; set; }

    /// <summary>
    /// Gets or sets which folders map to what roles in RBAC.
    /// </summary>
    [XmlArray("FolderRoleMappings")]
    [XmlArrayItem(typeof(FolderRoleMap), ElementName = "FolderRoleMappings")]
    public List<FolderRoleMap> FolderRoleMapping { get; set; }

    /// <summary>
    /// Gets or sets the default provider the user after logging in with SSO.
    /// </summary>
    public string DefaultProvider { get; set; }

    /// <summary>
    /// Gets or sets the redirect scheme override.
    /// </summary>
    public string SchemeOverride { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether the new, more descriptive paths are to be used.
    /// </summary>
    public bool NewPath { get; set; }

    /// <summary>
    /// Gets or sets a mapping of canonical names from the provider to jellyfin user ids.
    /// </summary>
    [XmlElement("CanonicalLinks")]
    public SerializableDictionary<string, Guid> CanonicalLinks
    {
        get
        {
            if (_canonicalLinks == null)
            {
                return new SerializableDictionary<string, Guid>();
            }

            return _canonicalLinks;
        }
        set => _canonicalLinks = value;
    }
}

/// <summary>
/// The configuration required for a OpenID flow.
/// </summary>
[XmlRoot("PluginConfiguration")]
public class OidConfig
{
    private SerializableDictionary<string, Guid> _canonicalLinks;

    /// <summary>
    /// Gets or sets the OpenID well-known information endpoint.
    /// </summary>
    public string OidEndpoint { get; set; }

    /// <summary>
    /// Gets or sets OpenID client ID.
    /// </summary>
    public string OidClientId { get; set; }

    /// <summary>
    /// Gets or sets OpenID shared secret.
    /// </summary>
    public string OidSecret { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether the provider is enabled.
    /// </summary>
    public bool Enabled { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether RBAC is enabled.
    /// </summary>
    public bool EnableAuthorization { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether all folders are allowed by default.
    /// </summary>
    public bool EnableAllFolders { get; set; }

    /// <summary>
    /// Gets or sets what folders should users have access to by default.
    /// </summary>
    public string[] EnabledFolders { get; set; }

    /// <summary>
    /// Gets or sets the roles that are checked to determine whether the user is an administrator.
    /// </summary>
    public string[] AdminRoles { get; set; }

    /// <summary>
    /// Gets or sets what roles are checked to determine whether the user is allowed to use Jellyfin.
    /// </summary>
    public string[] Roles { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether RBAC is used to manage folder access.
    /// </summary>
    public bool EnableFolderRoles { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether RBAC is used to manage Live TV access.
    /// </summary>
    public bool EnableLiveTvRoles { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether Live TV is enabled by default.
    /// </summary>
    public bool EnableLiveTv { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether Live TV is allowed to be managed by default.
    /// </summary>
    public bool EnableLiveTvManagement { get; set; }

    /// <summary>
    /// Gets or sets the roles that are checked to determine whether the user is allowed to view Live TV.
    /// </summary>
    public string[] LiveTvRoles { get; set; }

    /// <summary>
    /// Gets or sets the roles that are checked to determine whether the user is allowed to manage Live TV.
    /// </summary>
    public string[] LiveTvManagementRoles { get; set; }

    /// <summary>
    /// Gets or sets which folders map to what roles in RBAC.
    /// </summary>
    [XmlArray("FolderRoleMappings")]
    [XmlArrayItem(typeof(FolderRoleMap), ElementName = "FolderRoleMappings")]
    public List<FolderRoleMap> FolderRoleMapping { get; set; }

    /// <summary>
    /// Gets or sets the claim to check roles against. Separated by "."s.
    /// </summary>
    public string RoleClaim { get; set; }

    /// <summary>
    /// Gets or Sets additional Scopes to request access to in the authorization request.
    /// </summary>
    public string[] OidScopes { get; set; }

    /// <summary>
    /// Gets or sets the default provider the user after logging in with SSO.
    /// </summary>
    public string DefaultProvider { get; set; }

    /// <summary>
    /// Gets or sets the redirect scheme override.
    /// </summary>
    public string SchemeOverride { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether the new, more descriptive paths are to be used.
    /// </summary>
    public bool NewPath { get; set; }

    /// <summary>
    /// Gets or sets a mapping of canonical names from the provider to jellyfin user ids.
    /// </summary>
    [XmlElement("CanonicalLinks")]
    public SerializableDictionary<string, Guid> CanonicalLinks
    {
        get
        {
            if (_canonicalLinks == null)
            {
                return new SerializableDictionary<string, Guid>();
            }

            return _canonicalLinks;
        }
        set => _canonicalLinks = value;
    }

    /// <summary>
    /// Gets or sets the default username claim when creating new accounts.
    /// </summary>
    public string DefaultUsernameClaim { get; set; }

    /// <summary>
    /// Gets or sets the URL format of the new user avatar.
    /// </summary>
    public string AvatarUrlFormat { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether HTTPS in the discovery endpoint is required.
    /// </summary>
    public bool DisableHttps { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether the OpenID endpoints are validated.
    /// </summary>
    public bool DoNotValidateEndpoints { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether the OpenID issuer name is validated.
    /// </summary>
    public bool DoNotValidateIssuerName { get; set; }
}

/// <summary>
/// The OpenID client ID.
/// </summary>
public class FolderRoleMap
{
    /// <summary>
    /// Gets or sets the role of the mapping.
    /// </summary>
    public string Role { get; set; }

    /// <summary>
    /// Gets or sets the folders that are allowed from the given role.
    /// </summary>
    public List<string> Folders { get; set; }
}
