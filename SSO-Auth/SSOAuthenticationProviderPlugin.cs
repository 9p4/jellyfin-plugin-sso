using System;
using Jellyfin.Data.Entities;
using Jellyfin.Data.Enums;

namespace Jellyfin.Plugin.SSO_Auth {
    public class SSOAuthenticationProviderPlugin {
      private readonly ILogger<SSOAuthenticationProviderPlugin> _logger;
      private readonly IApplicationHost _applicationHost;

      public SSOAuthenticationProviderPlugin(IApplicationHost applicationHost, ILogger<SSOAuthenticationProviderPlugin> logger) {
        _logger = logger;
        _applicationHost = applicationHost;
      }

      public string Name => "SSO-Authentication";

      public bool isEnabled => true;
    }
}
