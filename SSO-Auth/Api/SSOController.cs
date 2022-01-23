using System;
using System.Collections.Generic;
using System.Net.Mime;
using System.Threading.Tasks;
using IdentityModel.OidcClient;
using Jellyfin.Data.Entities;
using Jellyfin.Data.Enums;
using Jellyfin.Plugin.SSO_Auth.Config;
using MediaBrowser.Controller.Authentication;
using MediaBrowser.Controller.Library;
using MediaBrowser.Controller.Session;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;

namespace Jellyfin.Plugin.SSO_Auth.Api;

/// <summary>
/// The sso api controller.
/// </summary>
[ApiController]
[Route("[controller]")]
public class SSOController : ControllerBase
{
    private readonly IUserManager _userManager;
    private readonly ISessionManager _sessionManager;
    private readonly ILogger<SSOController> _logger;
    private static readonly IDictionary<string, TimedAuthorizeState> StateManager = new Dictionary<string, TimedAuthorizeState>();

    /// <summary>
    /// Initializes a new instance of the <see cref="SSOController"/> class.
    /// </summary>
    /// <param name="logger">Instance of the <see cref="ILogger{SSOController}"/> interface.</param>
    /// <param name="sessionManager">Instance of the <see cref="ISessionManager"/> interface.</param>
    /// <param name="userManager">Instance of the <see cref="IUserManager"/> interface.</param>
    public SSOController(ILogger<SSOController> logger, ISessionManager sessionManager, IUserManager userManager)
    {
        _sessionManager = sessionManager;
        _userManager = userManager;
        _logger = logger;
        _logger.LogInformation("SSO Controller initialized");
    }

    [HttpGet("OID/r/{provider}")]
    public ActionResult OIDPost(string provider)
    {
        // Actually a GET: https://github.com/IdentityModel/IdentityModel.OidcClient/issues/325
        foreach (var config in SSOPlugin.Instance.Configuration.OIDConfigs)
        {
            if (config.OIDClientId == provider && config.Enabled)
            {
                var options = new OidcClientOptions
                {
                    Authority = config.OIDEndpoint,
                    ClientId = config.OIDClientId,
                    ClientSecret = config.OIDSecret,
                    RedirectUri = GetRequestBase() + "/sso/OID/r/" + provider,
                    Scope = "openid profile"
                };
                var oidcClient = new OidcClient(options);
                var state = StateManager[Request.Query["state"]].State;
                var result = oidcClient.ProcessResponseAsync(Request.QueryString.Value, state).Result;
                if (result.IsError)
                {
                    return Content("Something went wrong...", MediaTypeNames.Text.Plain);
                }

                foreach (var claim in result.User.Claims)
                {
                    if (claim.Type == "preferred_username")
                    {
                        StateManager[Request.Query["state"]].Username = claim.Value;
                        if (config.Roles.Length == 0)
                        {
                            StateManager[Request.Query["state"]].Valid = true;
                        }
                    }

                    // Check if allowed to login based on realm roles
                    if (config.Roles.Length != 0)
                    {
                        if (claim.Type == "realm_access") // This is specific to Keycloak. Don't use roles without Keycloak, I guess
                        {
                            List<string> roles = JsonConvert.DeserializeObject<IDictionary<string, List<string>>>(claim.Value)["roles"]; // Might need error handling here
                            foreach (string validRoles in config.Roles)
                            {
                                foreach (string role in roles)
                                {
                                    if (role.Equals(validRoles))
                                    {
                                        StateManager[Request.Query["state"]].Valid = true;
                                    }
                                }
                            }
                        }
                    }
                    // Check if admin
                    if (config.AdminRoles.Length != 0)
                    {
                        if (claim.Type == "realm_access") // This is specific to Keycloak. Don't use roles without Keycloak, I guess
                        {
                            List<string> roles = JsonConvert.DeserializeObject<IDictionary<string, List<string>>>(claim.Value)["roles"]; // Might need error handling here
                            foreach (string validAdminRoles in config.AdminRoles)
                            {
                                foreach (string role in roles)
                                {
                                    if (role.Equals(validAdminRoles))
                                    {
                                        StateManager[Request.Query["state"]].Admin = true;
                                    }
                                }
                            }
                        }
                    }
                }
                if (StateManager[Request.Query["state"]].Valid)
                {
                    return Content(WebResponse.OIDGenerator(data: Request.Query["state"], provider: provider, baseUrl: GetRequestBase()), MediaTypeNames.Text.Html);
                }
                else
                {
                    return Content("Error. Check permissions");
                }
            }
        }

        return Content("no active providers found"); // TODO: Return error code as well
    }

    [HttpGet("OID/p/{provider}")]
    public async Task<ActionResult> OIDChallenge(string provider)
    {
        Invalidate();
        foreach (var config in SSOPlugin.Instance.Configuration.OIDConfigs)
        {
            if (config.OIDClientId == provider && config.Enabled)
            {
                var options = new OidcClientOptions
                {
                    Authority = config.OIDEndpoint,
                    ClientId = config.OIDClientId,
                    ClientSecret = config.OIDSecret,
                    RedirectUri = GetRequestBase() + "/sso/OID/r/" + provider,
                    Scope = "openid profile"
                };
                var oidcClient = new OidcClient(options);
                var state = await oidcClient.PrepareLoginAsync().ConfigureAwait(false);
                StateManager.Add(state.State, new TimedAuthorizeState(state, DateTime.Now));
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
        for (var i = 0; i < configuration.OIDConfigs.Count; i++)
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
    [HttpGet("OID/Del/{provider}")]
    public void OIDDel(string provider)
    {
        var configuration = SSOPlugin.Instance.Configuration;
        for (var i = 0; i < configuration.OIDConfigs.Count; i++)
        {
            if (configuration.OIDConfigs[i].OIDClientId.Equals(provider))
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
        return Ok(StateManager);
    }

    [HttpPost("OID/Auth")]
    [Consumes(MediaTypeNames.Application.Json)]
    [Produces(MediaTypeNames.Application.Json)]
    public async Task<ActionResult> OIDAuth([FromBody] AuthResponse response)
    {
        foreach (var oidConfig in SSOPlugin.Instance.Configuration.OIDConfigs)
        {
            if (oidConfig.OIDClientId == response.Provider && oidConfig.Enabled)
            {
                foreach (var kvp in StateManager)
                {
                    if (kvp.Value.State.State.Equals(response.Data) && kvp.Value.Valid)
                    {
                        var authenticationResult = await Authenticate(kvp.Value.Username, kvp.Value.Admin, oidConfig.EnableAllFolders, oidConfig.EnabledFolders, response)
                            .ConfigureAwait(false);
                        return Ok(authenticationResult);
                    }
                }
            }
        }

        return Problem("Something went wrong");
    }

    [HttpPost("SAML/p/{provider}")]
    public ActionResult SAMLPost(string provider)
    {
        // I'm sure there's a better way than using nested for loops but eh whatever
        foreach (var samlConfig in SSOPlugin.Instance.Configuration.SamlConfigs)
        {
            if (samlConfig.SamlClientId == provider && samlConfig.Enabled)
            {
                var samlResponse = new Response(samlConfig.SamlCertificate, Request.Form["SAMLResponse"]);
                if (samlConfig.Roles.Length == 0)
                {
                    return Content(WebResponse.SamlGenerator(xml: Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(samlResponse.Xml)), provider: provider, baseUrl: GetRequestBase()), MediaTypeNames.Text.Html);
                }
                foreach (string role in samlResponse.GetCustomAttributes("Role"))
                {
                    foreach (string allowedRole in samlConfig.Roles)
                    {
                        if (allowedRole.Equals(role))
                        {
                            return Content(WebResponse.SamlGenerator(xml: Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(samlResponse.Xml)), provider: provider, baseUrl: GetRequestBase()), MediaTypeNames.Text.Html);
                        }
                    }
                }
                return Content("401 Forbidden");
            }
        }

        return Content("no active providers found"); // TODO: Return error code as well
    }

    [HttpGet("SAML/p/{provider}")]
    public RedirectResult SAMLChallenge(string provider)
    {
        foreach (var config in SSOPlugin.Instance.Configuration.SamlConfigs)
        {
            if (config.SamlClientId == provider && config.Enabled)
            {
                var request = new AuthRequest(
                    config.SamlClientId,
                    GetRequestBase() + "/sso/SAML/p/" + provider);

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
        for (var i = 0; i < configuration.SamlConfigs.Count; i++)
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
    [HttpGet("SAML/Del/{provider}")]
    public void SamlDel(string provider)
    {
        var configuration = SSOPlugin.Instance.Configuration;
        for (var i = 0; i < configuration.SamlConfigs.Count; i++)
        {
            if (configuration.SamlConfigs[i].SamlClientId.Equals(provider))
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
    public async Task<ActionResult> SamlAuth([FromBody] AuthResponse response)
    {
        foreach (var samlConfig in SSOPlugin.Instance.Configuration.SamlConfigs)
        {
            if (samlConfig.SamlClientId == response.Provider && samlConfig.Enabled)
            {
                bool isAdmin = false;
                var samlResponse = new Response(samlConfig.SamlCertificate, response.Data);
                foreach (string role in samlResponse.GetCustomAttributes("Role"))
                {
                    foreach (string allowedRole in samlConfig.AdminRoles)
                    {
                        if (allowedRole.Equals(role))
                        {
                            isAdmin = true;
                        }
                    }
                }
                var authenticationResult = await Authenticate(samlResponse.GetNameID(), isAdmin, samlConfig.EnableAllFolders, samlConfig.EnabledFolders, response)
                    .ConfigureAwait(false);
                return Ok(authenticationResult);
            }
        }

        return Problem("Something went wrong");
    }

    private async Task<AuthenticationResult> Authenticate(string username, bool isAdmin, bool enableAllFolders, string[] enabledFolders, AuthResponse authResponse)
    {
        User user = null;
        user = _userManager.GetUserByName(username);

        if (user == null)
        {
            _logger.LogInformation("SSO user doesn't exist, creating...");
            user = await _userManager.CreateUserAsync(username).ConfigureAwait(false);
        }
        user.AuthenticationProviderId = GetType().FullName;
        user.SetPermission(PermissionKind.IsAdministrator, isAdmin);
        user.SetPermission(PermissionKind.EnableAllFolders, enableAllFolders);
        if (!enableAllFolders)
        {
            user.SetPreference(PreferenceKind.EnabledFolders, enabledFolders);
        }

        await _userManager.UpdateUserAsync(user).ConfigureAwait(false);

        var authRequest = new AuthenticationRequest();
        authRequest.UserId = user.Id;
        authRequest.Username = user.Username;
        authRequest.App = authResponse.AppName;
        authRequest.AppVersion = authResponse.AppVersion;
        authRequest.DeviceId = authResponse.DeviceID;
        authRequest.DeviceName = authResponse.DeviceName;
        _logger.LogInformation("Auth request created...");
        return await _sessionManager.AuthenticateDirect(authRequest).ConfigureAwait(false);
    }

    private void Invalidate()
    {
        foreach (var kvp in StateManager)
        {
            var now = DateTime.Now;
            if (now.Subtract(kvp.Value.Created).TotalMinutes > 1)
            {
                StateManager.Remove(kvp.Key);
            }
        }
    }

    private string GetRequestBase()
    {
        return Request.Scheme + "://" + Request.Host + Request.PathBase;
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
        State = state;
        Created = created;
        Valid = false;
        Admin = false;
    }

    public AuthorizeState State { get; set; }

    public DateTime Created { get; set; }

    public bool Valid { get; set; }

    public string Username { get; set; }

    public bool Admin { get; set; }
}
