using System;
using System.Net.Mime;
using System.Collections.Generic;
using MediaBrowser.Controller.Session;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.Authorization;
using IdentityModel.OidcClient;
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
        private static IDictionary<string, TimedAuthorizeState> _stateManager = new Dictionary<string, TimedAuthorizeState>();

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
                    return Content(WebResponse.SamlGenerator(xml: Convert.ToBase64String(System.Text.UTF8Encoding.UTF8.GetBytes(samlResponse.Xml)), provider: provider), "text/html");
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

        [HttpGet("OID/r/{provider}")]
        public ActionResult OIDPost(string provider)
        {
            // Actually a GET: https://github.com/IdentityModel/IdentityModel.OidcClient/issues/325
            foreach (OIDConfig config in SSOPlugin.Instance.Configuration.OIDConfigs)
            {
                if (config.OIDClientId == provider && config.Enabled)
                {
                    var options = new OidcClientOptions
                    {
                        Authority = config.OIDEndpoint,
                        ClientId = config.OIDClientId,
                        ClientSecret = config.OIDSecret,
                        RedirectUri = "http://" + Request.Host.Value + "/sso/OID/r/" + provider,
                        Scope = "openid profile"
                    };
                    OidcClient oidcClient = new OidcClient(options);
                    var state = _stateManager[Request.Query["state"]].State;
                    var result = oidcClient.ProcessResponseAsync(Request.QueryString.Value, state).Result;
                    if (result.IsError)
                    {
                        return Content("Something went wrong...", "text/plain");
                    }
                    foreach (var claim in result.User.Claims)
                    {
                        _logger.LogWarning("{0}: {1}", claim.Type, claim.Value);
                        if (claim.Type == "preferred_username")
                        {
                            _stateManager[Request.Query["state"]].Valid = true;
                            _stateManager[Request.Query["state"]].Username = claim.Value;
                            return Content(WebResponse.OIDGenerator(data: Request.Query["state"], provider: provider), "text/html");
                        }
                    }
                    return Content("Does your OpenID provider not support the preferred_username value?", "text/plain");
                }
            }
            return Content("no active providers found"); // TODO: Return error code as well
        }

        [HttpGet("OID/p/{provider}")]
        public ActionResult OIDChallenge(string provider)
        {
            Invalidate();
            foreach (OIDConfig config in SSOPlugin.Instance.Configuration.OIDConfigs)
            {
                if (config.OIDClientId == provider && config.Enabled)
                {
                    var options = new OidcClientOptions
                    {
                        Authority = config.OIDEndpoint,
                        ClientId = config.OIDClientId,
                        ClientSecret = config.OIDSecret,
                        RedirectUri = "http://" + Request.Host.Value + "/sso/OID/r/" + provider,
                        Scope = "openid profile"
                    };
                    OidcClient oidcClient = new OidcClient(options);
                    AuthorizeState state = oidcClient.PrepareLoginAsync().Result;
                    _stateManager.Add(state.State, new TimedAuthorizeState(state, DateTime.Now));
                    return Redirect(state.StartUrl);
                }
            }
            throw new ArgumentException("Provider does not exist");
        }

        [Authorize(Policy = "RequiresElevation")]
        [HttpPost("OID/Add")]
        public void OIDAdd([FromBody] OIDConfig oidConfig)
        {
            var configuration = SSOPlugin.Instance.Configuration;
            for (int i = 0; i < configuration.OIDConfigs.Count; i++)
            {
                if (configuration.OIDConfigs[i].OIDClientId.Equals(oidConfig.OIDClientId))
                {
                    configuration.OIDConfigs.RemoveAt(i);
                }
            }
            configuration.OIDConfigs.Add(oidConfig);
            SSOPlugin.Instance.UpdateConfiguration(configuration);
        }

        [Authorize(Policy = "RequiresElevation")]
        [HttpPost("OID/Del")]
        public void OIDDel([FromBody] OIDConfig oidConfig)
        {
            var configuration = SSOPlugin.Instance.Configuration;
            for (int i = 0; i < configuration.OIDConfigs.Count; i++)
            {
                if (configuration.OIDConfigs[i].OIDClientId.Equals(oidConfig.OIDClientId))
                {
                    configuration.OIDConfigs.RemoveAt(i);
                }
            }
            SSOPlugin.Instance.UpdateConfiguration(configuration);
        }


        [Authorize(Policy = "RequiresElevation")]
        [HttpGet("OID/Get")]
        public ActionResult OIDProviders()
        {
            return Ok(SSOPlugin.Instance.Configuration.OIDConfigs);
        }

        [Authorize(Policy = "RequiresElevation")]
        [HttpGet("OID/States")]
        public ActionResult OIDStates()
        {
            return Ok(_stateManager);
        }

        [HttpPost("OID/Auth")]
        [Consumes(MediaTypeNames.Application.Json)]
        [Produces(MediaTypeNames.Application.Json)]
        public ActionResult OIDAuth([FromBody] AuthResponse response)
        {
            foreach (OIDConfig oidConfig in SSOPlugin.Instance.Configuration.OIDConfigs)
            {
                if (oidConfig.OIDClientId == response.Provider && oidConfig.Enabled)
                {
                    foreach (KeyValuePair<string, TimedAuthorizeState> kvp in _stateManager)
                    {
                      if (kvp.Value.State.State.Equals(response.Data) && kvp.Value.Valid) {
                        AuthenticationResult authenticationResult = Authenticate(kvp.Value.Username, false, oidConfig.EnableAllFolders, oidConfig.EnabledFolders, response).Result;
                        return Ok(authenticationResult);
                      }
                    }
                }
            }
            return Problem("Something went wrong");
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
            return Ok(SSOPlugin.Instance.Configuration.SamlConfigs);
        }

        [HttpPost("SAML/Auth")]
        [Consumes(MediaTypeNames.Application.Json)]
        [Produces(MediaTypeNames.Application.Json)]
        public ActionResult SamlAuth([FromBody] AuthResponse response)
        {
            foreach (SamlConfig samlConfig in SSOPlugin.Instance.Configuration.SamlConfigs)
            {
                if (samlConfig.SamlClientId == response.Provider && samlConfig.Enabled)
                {
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

            if (user == null)
            {
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

        private void Invalidate()
        {
            foreach (KeyValuePair<string, TimedAuthorizeState> kvp in _stateManager)
            {
                DateTime now = DateTime.Now;
                if (now.Subtract(kvp.Value.Created).TotalMinutes > 1)
                {
                    _stateManager.Remove(kvp.Key);
                }
            }
        }
    }

    public class AuthResponse
    {
        public string DeviceID { get; set; }
        public string DeviceName { get; set; }
        public string AppName { get; set; }
        public string AppVersion { get; set; }
        public string Data { get; set; }
        public string Provider { get; set; }
    }

    public class TimedAuthorizeState
    {
        public TimedAuthorizeState(AuthorizeState state, DateTime created)
        {
            this.State = state;
            this.Created = created;
            this.Valid = false;
        }
        public AuthorizeState State { get; set; }
        public DateTime Created { get; set; }
        public bool Valid { get; set; }
        public string Username { get; set; }
    }
}
