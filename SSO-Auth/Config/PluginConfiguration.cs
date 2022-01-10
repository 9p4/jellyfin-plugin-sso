using System;

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
            SamlEndpoint = "https://saml-provider.example.com/login";
            EntityID = "https://myjellyfin.example.com";
            SamlCertificate = @"-----BEGIN CERTIFICATE-----
BLAHBLAHBLAHBLAHBLAHBLAHBLAHBLAHBLAHBLAHBLAHBLAH123543==
-----END CERTIFICATE-----";
        }

        public string SamlEndpoint { get; set; }

        public string EntityID { get; set; }

        public string SamlCertificate { get; set; }

    }
}
