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
        SamlConfigs = new List<SamlConfig>();
        OIDConfigs = new List<OIDConfig>();
    }

    [XmlArray("SamlConfigs")]
    [XmlArrayItem(typeof(SamlConfig), ElementName = "SamlConfigs")]
    public List<SamlConfig> SamlConfigs { get; set; }

    [XmlArray("OIDConfigs")]
    [XmlArrayItem(typeof(OIDConfig), ElementName = "OIDConfigs")]
    public List<OIDConfig> OIDConfigs { get; set; }
}

[XmlRoot("PluginConfiguration")]
public class SamlConfig
{
    public string SamlEndpoint { get; set; }

    public string SamlClientId { get; set; }

    public string SamlCertificate { get; set; }

    public bool Enabled { get; set; }

    public bool EnableAllFolders { get; set; }

    public string[] EnabledFolders { get; set; }

    public string[] AdminRoles { get; set; }

    public string[] Roles { get; set; }
}

[XmlRoot("PluginConfiguration")]
public class OIDConfig
{
    public string OIDEndpoint { get; set; }

    public string OIDClientId { get; set; }

    public string OIDSecret { get; set; }

    public bool Enabled { get; set; }

    public bool EnableAllFolders { get; set; }

    public string[] EnabledFolders { get; set; }

    public string[] AdminRoles { get; set; }

    public string[] Roles { get; set; }
}
