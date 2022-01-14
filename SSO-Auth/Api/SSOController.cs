using System;
using System.Net.Mime;
using System.Collections.Generic;
using MediaBrowser.Controller.Session;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.Authorization;
using Jellyfin.Plugin.SSO_Auth.Config;
using Saml;
using MediaBrowser.Common;
using System.Threading.Tasks;
using Jellyfin.Data.Entities;
using Jellyfin.Data.Enums;
using MediaBrowser.Controller.Authentication;
using MediaBrowser.Controller.Library;

namespace Jellyfin.Plugin.SSO_Auth.Api
{
    /// <summary>
    /// The sso api controller.
    /// </summary>
    [ApiController]
    [Route("[controller]")]
    public class SSOController : ControllerBase
    {
        private readonly IApplicationHost _applicationHost;
        private readonly ISessionManager _sessionManager;
        private readonly ILogger<SSOController> _logger;

        public SSOController(IApplicationHost appHost, ILoggerFactory loggerFactory, ISessionManager sessionManager)
        {
            _applicationHost = appHost;
            _sessionManager = sessionManager;
            _logger = loggerFactory.CreateLogger<SSOController>();
            _logger.LogWarning("SSO Controller initialized");
        }

        [HttpPost("SAML/p/{provider}")]
        public ActionResult SAMLPost(string provider)
        {
            foreach (SamlConfig config in SSOPlugin.Instance.Configuration.SamlConfigs)
            {
                if (config.SamlClientId == provider && config.Enabled)
                {
                    Saml.Response samlResponse = new Saml.Response(config.SamlCertificate, Request.Form["SAMLResponse"]);
                    return Content(WebResponse.BuildGenerator(xml: Convert.ToBase64String(System.Text.UTF8Encoding.UTF8.GetBytes(samlResponse.Xml)), provider: provider), "text/html");
                }
            }
            return Content("no active providers found"); // TODO: Return error code as well
        }

        [HttpGet("SAML/p/{provider}")]
        public RedirectResult SAMLChallenge(string provider)
        {
            foreach (SamlConfig config in SSOPlugin.Instance.Configuration.SamlConfigs)
            {
                if (config.SamlClientId == provider && config.Enabled)
                {
                    var request = new AuthRequest(
                        config.SamlClientId,
                        "http://" + Request.Host.Value + "/sso/SAML/p/" + provider
                    );
                    return Redirect(request.GetRedirectUrl(config.SamlEndpoint));
                }
            }
            throw new ArgumentException("Provider does not exist");
        }

        [Authorize(Policy = "RequiresElevation")]
        [HttpPost("SAML/Add")]
        public void SamlAdd([FromBody] SamlConfig samlConfig)
        {
            var configuration = SSOPlugin.Instance.Configuration;
            for (int i = 0; i < configuration.SamlConfigs.Count; i++)
            {
                if (configuration.SamlConfigs[i].SamlClientId.Equals(samlConfig.SamlClientId))
                {
                    configuration.SamlConfigs.RemoveAt(i);
                }
            }
            configuration.SamlConfigs.Add(samlConfig);
            SSOPlugin.Instance.UpdateConfiguration(configuration);
        }

        [Authorize(Policy = "RequiresElevation")]
        [HttpPost("SAML/Del")]
        public void SamlDel([FromBody] SamlConfig samlConfig)
        {
            var configuration = SSOPlugin.Instance.Configuration;
            for (int i = 0; i < configuration.SamlConfigs.Count; i++)
            {
                if (configuration.SamlConfigs[i].SamlClientId.Equals(samlConfig.SamlClientId))
                {
                    configuration.SamlConfigs.RemoveAt(i);
                }
            }
            SSOPlugin.Instance.UpdateConfiguration(configuration);
        }


        [Authorize(Policy = "RequiresElevation")]
        [HttpGet("SAML/Get")]
        public ActionResult SamlProviders()
        {
            List<SamlConfig> samlConfigs = SSOPlugin.Instance.Configuration.SamlConfigs;
            return Ok(samlConfigs);
        }

        [HttpPost("SAML/Auth")]
        [Consumes(MediaTypeNames.Application.Json)]
        [Produces(MediaTypeNames.Application.Json)]
        public ActionResult SamlAuth([FromBody] AuthResponse response)
        {
          foreach (SamlConfig samlConfig in SSOPlugin.Instance.Configuration.SamlConfigs) {
            if (samlConfig.SamlClientId == response.Provider && samlConfig.Enabled) {
              Saml.Response samlResponse = new Saml.Response(samlConfig.SamlCertificate, response.Data);
              AuthenticationResult authenticationResult = Authenticate(samlResponse.GetNameID(), false, samlConfig.EnableAllFolders, samlConfig.EnabledFolders, response).Result;
              return Ok(authenticationResult);
            }
          }
          return Problem("Something went wrong");
        }

        private async Task<AuthenticationResult> Authenticate(string username, bool isAdmin, bool enableAllFolders, string[] enabledFolders, AuthResponse authResponse)
        {
            _logger.LogWarning("Authenticating");
            var userManager = _applicationHost.Resolve<IUserManager>();
            User user = null;
            user = userManager.GetUserByName(username);

            if (user == null) {
                _logger.LogWarning("SSO user doesn't exist, creating...");
                user = await userManager.CreateUserAsync(username).ConfigureAwait(false);
                user.AuthenticationProviderId = GetType().FullName;
                user.SetPermission(PermissionKind.IsAdministrator, isAdmin);
                user.SetPermission(PermissionKind.EnableAllFolders, enableAllFolders);
                if (!enableAllFolders)
                {
                    user.SetPreference(PreferenceKind.EnabledFolders, enabledFolders);
                }

                await userManager.UpdateUserAsync(user).ConfigureAwait(false);
            }

            AuthenticationRequest authRequest = new AuthenticationRequest();
            authRequest.UserId = user.Id;
            authRequest.Username = user.Username;
            authRequest.App = authResponse.AppName;
            authRequest.AppVersion = authResponse.AppVersion;
            authRequest.DeviceId = authResponse.DeviceID;
            authRequest.DeviceName = authResponse.DeviceName;
            _logger.LogWarning("Auth request created...");
            return _sessionManager.AuthenticateDirect(authRequest).Result;
        }
    }

    public class AuthResponse {
      public string DeviceID { get; set; }
      public string DeviceName { get; set; }
      public string AppName { get; set; }
      public string AppVersion { get; set; }
      public string Data { get; set; }
      public string Provider { get; set; }
    }
}
