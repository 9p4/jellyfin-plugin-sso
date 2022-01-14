using System.Collections.Generic;
using System.Xml.Serialization;

namespace Jellyfin.Plugin.SSO_Auth.Config {
    /// <summary>
    /// Plugin Configuration.
    /// </summary>
    public class PluginConfiguration : MediaBrowser.Model.Plugins.BasePluginConfiguration {
        /// <summary>
        /// Initializes a new instance of the <see cref="PluginConfiguration"/> class.
        /// </summary>
        public PluginConfiguration()
        {
          SamlConfigs = new List<SamlConfig>();
        }

        [XmlArray("SamlConfigs"), XmlArrayItem(typeof(SamlConfig), ElementName = "SamlConfigs")]
        public List<SamlConfig> SamlConfigs { get; set; }

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
    }
}
