using System;
using System.Collections.Generic;
using Jellyfin.Plugin.SSO_Auth.Config;
using MediaBrowser.Common.Configuration;
using MediaBrowser.Common.Plugins;
using MediaBrowser.Model.Plugins;
using MediaBrowser.Model.Serialization;

namespace Jellyfin.Plugin.SSO_Auth {
  public class SSOPlugin : BasePlugin<PluginConfiguration>, IHasWebPages {
    public SSOPlugin(IApplicationPaths applicationPaths, IXmlSerializer xmlSerializer) : base(applicationPaths, xmlSerializer) {
      Instance = this;
    }

    public static SSOPlugin Instance { get; private set; }

    public override string Name => "SSO-Auth";

    public override Guid Id => Guid.Parse("505ce9d1-d916-42fa-86ca-673ef241d7df");

    public IEnumerable<PluginPageInfo> GetPages() {
      return new[] {
        new PluginPageInfo {
          Name = Name,
          EmbeddedResourcePath = $"{GetType().Namespace}.Config.configPage.html"
        }
      };
    }
  }
}
