using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Mime;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Duende.IdentityModel.Client;
using Duende.IdentityModel.OidcClient;
using Jellyfin.Data;
using Jellyfin.Database.Implementations.Entities;
using Jellyfin.Database.Implementations.Enums;
using Jellyfin.Plugin.SSO_Auth.Config;
using Jellyfin.Plugin.SSO_Auth.Helpers;
using MediaBrowser.Common.Api;
using MediaBrowser.Controller.Authentication;
using MediaBrowser.Controller.Configuration;
using MediaBrowser.Controller.Library;
using MediaBrowser.Controller.Net;
using MediaBrowser.Controller.Providers;
using MediaBrowser.Controller.Session;
using MediaBrowser.Model.Cryptography;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

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
    private readonly IAuthorizationContext _authContext;
    private readonly ILogger<SSOController> _logger;
    private readonly ILoggerFactory _loggerFactory;
    private readonly ICryptoProvider _cryptoProvider;
    private readonly IProviderManager _providerManager;
    private readonly IServerConfigurationManager _serverConfigurationManager;
    private static readonly IDictionary<string, TimedAuthorizeState> StateManager = new Dictionary<string, TimedAuthorizeState>();
    private static readonly IDictionary<string, DeviceCodeState> DeviceCodeStateManager = new Dictionary<string, DeviceCodeState>();

    /// <summary>
    /// Extracts username from claims based on configuration.
    /// </summary>
    private static string ExtractUsername(JObject claims, OidConfig config)
    {
        var usernameClaim = config.DefaultUsernameClaim?.Trim() ?? "preferred_username";
        return claims[usernameClaim]?.ToString() ?? claims["sub"]?.ToString();
    }

    /// <summary>
    /// Processes role claims and determines user permissions.
    /// </summary>
    private (bool IsValid, bool IsAdmin, List<string> Folders, bool EnableLiveTv, bool EnableLiveTvManagement) ProcessRoleClaims(
        JObject claims,
        OidConfig config)
    {
        bool isValid = config.Roles == null || config.Roles.Length == 0;
        bool isAdmin = false;
        List<string> folders = new List<string>();
        bool enableLiveTv = config.EnableLiveTv;
        bool enableLiveTvManagement = config.EnableLiveTvManagement;

        // Set default folders
        if (!config.EnableFolderRoles && config.EnabledFolders != null)
        {
            folders = new List<string>(config.EnabledFolders);
        }

        // Process role claim if configured
        if (!string.IsNullOrEmpty(config.RoleClaim))
        {
            string[] segments = Regex.Split(config.RoleClaim.Trim(), "(?<!\\\\)\\.")
                .Select(i => i.Replace("\\.", "."))
                .ToArray();

            var roleClaimValue = claims[segments[0]];
            List<string> roles = ExtractRoles(roleClaimValue, segments);

            // Process each role
            foreach (string role in roles)
            {
                // Check if allowed to login
                if (config.Roles != null && config.Roles.Any() && config.Roles.Contains(role))
                {
                    isValid = true;
                }

                // Check admin roles
                if (config.AdminRoles != null && config.AdminRoles.Contains(role))
                {
                    isAdmin = true;
                }

                // Process folder roles
                if (config.EnableFolderRoles && config.FolderRoleMapping != null)
                {
                    foreach (var folderRoleMap in config.FolderRoleMapping)
                    {
                        if (role.Equals(folderRoleMap.Role?.Trim()))
                        {
                            folders.AddRange(folderRoleMap.Folders);
                        }
                    }
                }

                // Process Live TV roles
                if (config.EnableLiveTvRoles)
                {
                    if (config.LiveTvRoles != null && config.LiveTvRoles.Contains(role))
                    {
                        enableLiveTv = true;
                    }

                    if (config.LiveTvManagementRoles != null && config.LiveTvManagementRoles.Contains(role))
                    {
                        enableLiveTvManagement = true;
                    }
                }
            }
        }

        return (isValid, isAdmin, folders, enableLiveTv, enableLiveTvManagement);
    }

    /// <summary>
    /// Extracts roles from claim value, handling nested JSON paths.
    /// </summary>
    private List<string> ExtractRoles(JToken roleClaimValue, string[] segments)
    {
        if (roleClaimValue == null)
        {
            return new List<string>();
        }

        if (segments.Length == 1)
        {
            // Direct role claim
            if (roleClaimValue is JArray rolesArray)
            {
                return rolesArray.ToObject<List<string>>();
            }

            return new List<string> { roleClaimValue.ToString() };
        }

        // Nested JSON path for roles
        try
        {
            var json = roleClaimValue.Type == JTokenType.String
                ? JsonConvert.DeserializeObject<IDictionary<string, object>>(roleClaimValue.ToString())
                : roleClaimValue.ToObject<IDictionary<string, object>>();

            for (int i = 1; i < segments.Length - 1; i++)
            {
                var segment = segments[i];
                json = (json[segment] as JObject)?.ToObject<IDictionary<string, object>>();
            }

            return (json[segments[^1]] as JArray)?.ToObject<List<string>>() ?? new List<string>();
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to parse role claim from nested JSON");
            return new List<string>();
        }
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="SSOController"/> class.
    /// </summary>
    /// <param name="logger">Instance of the <see cref="ILogger{SSOController}"/> interface.</param>
    /// <param name="loggerFactory">Instance of the <see cref="ILoggerFactory"/> interface.</param>
    /// <param name="sessionManager">Instance of the <see cref="ISessionManager"/> interface.</param>
    /// <param name="authContext">Instance of the <see cref="IAuthorizationContext"/> interface.</param>
    /// <param name="userManager">Instance of the <see cref="IUserManager"/> interface.</param>
    /// <param name="cryptoProvider">Instance of the <see cref="ICryptoProvider"/> interface.</param>
    /// <param name="providerManager">Instance of the <see cref="IProviderManager"/> interface.</param>
    /// <param name="serverConfigurationManager">Instance of the <see cref="IServerConfigurationManager"/> interface.</param>
    public SSOController(
        ILogger<SSOController> logger,
        ILoggerFactory loggerFactory,
        ISessionManager sessionManager,
        IUserManager userManager,
        IAuthorizationContext authContext,
        ICryptoProvider cryptoProvider,
        IProviderManager providerManager,
        IServerConfigurationManager serverConfigurationManager)
    {
        _sessionManager = sessionManager;
        _userManager = userManager;
        _authContext = authContext;
        _cryptoProvider = cryptoProvider;
        _logger = logger;
        _loggerFactory = loggerFactory;
        _providerManager = providerManager;
        _serverConfigurationManager = serverConfigurationManager;
        _logger.LogInformation("SSO Controller initialized");
    }

    /// <summary>
    /// The GET endpoint for OpenID provider to callback to. Returns a webpage that parses client data and completes auth.
    /// </summary>
    /// <param name="provider">The ID of the provider which will use the callback information.</param>
    /// <param name="state">The current request state.</param>
    /// <returns>A webpage that will complete the client-side flow.</returns>
    // Actually a GET: https://github.com/IdentityModel/IdentityModel.OidcClient/issues/325
    [HttpGet("OID/r/{provider}")]
    [HttpGet("OID/redirect/{provider}")]
    public async Task<ActionResult> OidPost(
        [FromRoute] string provider,
        [FromQuery] string state) // Although this is a GET function, this function is called `Post` for consistency with SAML
    {
        OidConfig config;
        try
        {
            config = SSOPlugin.Instance.Configuration.OidConfigs[provider];
        }
        catch (KeyNotFoundException)
        {
            return BadRequest("No matching provider found");
        }

        if (config.Enabled)
        {
            var scopes = config.OidScopes == null ? new string[2] : config.OidScopes;
            var options = new OidcClientOptions
            {
                Authority = config.OidEndpoint?.Trim(),
                ClientId = config.OidClientId?.Trim(),
                ClientSecret = config.OidSecret?.Trim(),
                RedirectUri = GetRequestBase(config.SchemeOverride, config.PortOverride) + $"/sso/OID/{(Request.Path.Value.Contains("/start/", StringComparison.InvariantCultureIgnoreCase) ? "redirect" : "r")}/" + provider,
                Scope = string.Join(" ", scopes.Prepend("openid profile")),
                DisablePushedAuthorization = config.DisablePushedAuthorization,
                LoggerFactory = _loggerFactory,
                LoadProfile = !config.DoNotLoadProfile,
            };
            var oidEndpointUri = new Uri(config.OidEndpoint?.Trim());
            options.Policy.Discovery.AdditionalEndpointBaseAddresses.Add(oidEndpointUri.GetLeftPart(UriPartial.Authority));
            options.Policy.Discovery.ValidateEndpoints = !config.DoNotValidateEndpoints; // For Google and other providers with different endpoints
            options.Policy.Discovery.RequireHttps = !config.DisableHttps;
            options.Policy.Discovery.ValidateIssuerName = !config.DoNotValidateIssuerName;
            var oidcClient = new OidcClient(options);
            var currentState = StateManager[state].State;
            var result = await oidcClient.ProcessResponseAsync(Request.QueryString.Value, currentState).ConfigureAwait(false);

            if (result.IsError)
            {
                return ReturnError(StatusCodes.Status400BadRequest, $"Error logging in: {result.Error} - {result.ErrorDescription}");
            }

            // Convert claims to JObject for processing
            var claimsDict = new JObject();
            foreach (var claim in result.User.Claims)
            {
                if (claimsDict.ContainsKey(claim.Type))
                {
                    // Handle multiple values for same claim
                    if (claimsDict[claim.Type] is JArray arr)
                    {
                        arr.Add(claim.Value);
                    }
                    else
                    {
                        var existingValue = claimsDict[claim.Type].ToString();
                        claimsDict[claim.Type] = new JArray { existingValue, claim.Value };
                    }
                }
                else
                {
                    claimsDict[claim.Type] = claim.Value;
                }
            }

            // Extract username
            StateManager[state].Username = ExtractUsername(claimsDict, config);

            // Process roles and permissions
            var (isValid, isAdmin, folders, enableLiveTv, enableLiveTvManagement) = ProcessRoleClaims(claimsDict, config);
            StateManager[state].Valid = isValid;
            StateManager[state].Admin = isAdmin;
            StateManager[state].Folders = folders;
            StateManager[state].EnableLiveTv = enableLiveTv;
            StateManager[state].EnableLiveTvManagement = enableLiveTvManagement;

            // Process avatar URL
            if (config.AvatarUrlFormat is not null)
            {
                StateManager[state].AvatarURL = config.AvatarUrlFormat;
                foreach (var claim in claimsDict)
                {
                    StateManager[state].AvatarURL = StateManager[state].AvatarURL.Replace(
                        $"@{{{claim.Key}}}",
                        claim.Value?.ToString() ?? string.Empty);
                }
            }

            bool isLinking = StateManager[state].IsLinking;

            if (StateManager[state].Valid)
            {
                _logger.LogInformation($"Is request linking: {isLinking}");
                return Content(WebResponse.Generator(data: state, provider: provider, baseUrl: GetRequestBase(config.SchemeOverride, config.PortOverride), mode: "OID", isLinking: isLinking), MediaTypeNames.Text.Html);
            }
            else
            {
                _logger.LogWarning(
                    "OpenID user {Username} has one or more incorrect role claims: {@Claims}. Expected any one of: {@ExpectedClaims}",
                    StateManager[state].Username,
                    result.User.Claims.Select(o => new { o.Type, o.Value }),
                    config.Roles);

                return ReturnError(StatusCodes.Status401Unauthorized, "Error. Check permissions.");
            }
        }

        // If the config doesn't have an active provider matching the requeset, show an error
        return BadRequest("No matching provider found");
    }

    /// <summary>
    /// Initiates the login flow for OpenID. This redirects the user to the auth provider.
    /// </summary>
    /// <param name="provider">The name of the provider.</param>
    /// <param name="isLinking">Whether or not this request is to link accounts (Rather than authenticate).</param>
    /// <returns>An asynchronous result for the authentication.</returns>
    [HttpGet("OID/p/{provider}")]
    [HttpGet("OID/start/{provider}")]
    public async Task<ActionResult> OidChallenge(string provider, [FromQuery] bool isLinking = false)
    {
        Invalidate();
        OidConfig config;
        try
        {
            config = SSOPlugin.Instance.Configuration.OidConfigs[provider];
        }
        catch (KeyNotFoundException)
        {
            throw new ArgumentException("Provider does not exist");
        }

        if (config.Enabled)
        {
            bool newPath = config.NewPath;
            if (!isLinking)
            {
                newPath = Request.Path.Value.Contains("/start/", StringComparison.InvariantCultureIgnoreCase);
                config.NewPath = newPath;
            }

            string redirectUri = GetRequestBase(config.SchemeOverride, config.PortOverride) + $"/sso/OID/{(newPath ? "redirect" : "r")}/" + provider;

            var options = new OidcClientOptions
            {
                Authority = config.OidEndpoint?.Trim(),
                ClientId = config.OidClientId?.Trim(),
                ClientSecret = config.OidSecret?.Trim(),
                RedirectUri = redirectUri,
                Scope = string.Join(" ", config.OidScopes.Prepend("openid profile")),
                DisablePushedAuthorization = config.DisablePushedAuthorization,
                LoggerFactory = _loggerFactory,
                LoadProfile = !config.DoNotLoadProfile,
            };
            var oidEndpointUri = new Uri(config.OidEndpoint?.Trim());
            options.Policy.Discovery.AdditionalEndpointBaseAddresses.Add(oidEndpointUri.GetLeftPart(UriPartial.Authority));
            options.Policy.Discovery.ValidateEndpoints = !config.DoNotValidateEndpoints; // For Google and other providers with different endpoints
            options.Policy.Discovery.RequireHttps = !config.DisableHttps;
            options.Policy.Discovery.ValidateIssuerName = !config.DoNotValidateIssuerName;
            var oidcClient = new OidcClient(options);
            var state = await oidcClient.PrepareLoginAsync().ConfigureAwait(false);

            if (state.IsError)
            {
                return ReturnError(StatusCodes.Status400BadRequest, $"Error preparing login: {state.Error} - {state.ErrorDescription}");
            }

            StateManager.Add(state.State, new TimedAuthorizeState(state, DateTime.Now));

            // Track whether this is a linking request or not.
            StateManager[state.State].IsLinking = isLinking;
            return Redirect(state.StartUrl);
        }

        throw new ArgumentException("Provider does not exist");
    }

    /// <summary>
    /// Serves the HTML page for device code flow that will initiate the flow with PKCE.
    /// </summary>
    /// <param name="provider">The name of the provider.</param>
    /// <returns>HTML page that will initiate the device code flow.</returns>
    [HttpGet("OID/device/page/{provider}")]
    public ActionResult OidDevicePage(string provider)
    {
        var configuration = SSOPlugin.Instance.Configuration;

        if (!configuration.OidConfigs.TryGetValue(provider, out var config) || config == null)
        {
            return NotFound("Provider not found");
        }

        if (!config.DeviceAuthorizationGrantEnabled)
        {
            return BadRequest("Device authorization grant is not enabled for this provider");
        }

        if (!config.Enabled)
        {
            return BadRequest("Provider is not enabled");
        }

        var baseUrl = GetRequestBase(config.SchemeOverride, config.PortOverride);
        return Content(
            WebResponse.DeviceCodeGenerator(provider, baseUrl),
            "text/html");
    }

    /// <summary>
    /// Initiates the device code flow for OpenID with PKCE. Returns device code information.
    /// </summary>
    /// <param name="provider">The name of the provider.</param>
    /// <param name="request">The device authorization request containing code_challenge.</param>
    /// <returns>JSON with device code, user code, verification URI, and state.</returns>
    [HttpPost("OID/device/{provider}")]
    [Consumes(MediaTypeNames.Application.Json)]
    [Produces(MediaTypeNames.Application.Json)]
    public async Task<ActionResult> OidDeviceStart(string provider, [FromBody] DeviceAuthRequest request)
    {
        // Clean up old states
        var expiredStates = DeviceCodeStateManager
            .Where(kvp => DateTime.UtcNow > kvp.Value.Created.AddMinutes(10))
            .Select(kvp => kvp.Key)
            .ToList();

        foreach (var expiredState in expiredStates)
        {
            DeviceCodeStateManager.Remove(expiredState);
            _logger.LogDebug("Removed expired device state: {State}", expiredState);
        }

        var configuration = SSOPlugin.Instance.Configuration;

        if (!configuration.OidConfigs.TryGetValue(provider, out var config) || config == null)
        {
            return NotFound("Provider does not exist");
        }

        if (!config.DeviceAuthorizationGrantEnabled)
        {
            return Unauthorized("Device authorization grant is not enabled for this provider");
        }

        if (config.Enabled)
        {
            try
            {
                // Use IdentityModel client for discovery and device authorization
                using var httpClient = new HttpClient();
                var disco = await httpClient.GetDiscoveryDocumentAsync(new DiscoveryDocumentRequest
                {
                    Address = config.OidEndpoint?.Trim(),
                    Policy = new DiscoveryPolicy
                    {
                        AdditionalEndpointBaseAddresses = { new Uri(config.OidEndpoint?.Trim()).GetLeftPart(UriPartial.Authority) },
                        ValidateEndpoints = !config.DoNotValidateEndpoints,
                        RequireHttps = !config.DisableHttps,
                        ValidateIssuerName = !config.DoNotValidateIssuerName
                    }
                }).ConfigureAwait(false);

                if (disco.IsError)
                {
                    _logger.LogInformation("OidEnpoint: {Endpoint}", config.OidEndpoint);
                    _logger.LogError("Error discovering endpoints for provider {Provider}: {Error}", provider, disco.Error);
                    return StatusCode(StatusCodes.Status500InternalServerError, $"Discovery failed: {disco.Error}");
                }

                if (string.IsNullOrEmpty(disco.DeviceAuthorizationEndpoint))
                {
                    _logger.LogError("Device authorization endpoint not found in discovery document for provider {Provider}", provider);
                    return BadRequest("Device authorization endpoint not found");
                }

                _logger.LogInformation("Using device authorization endpoint: {Endpoint}", disco.DeviceAuthorizationEndpoint);

                // Make request to device authorization endpoint using IdentityModel
                var deviceResponse = await httpClient.RequestDeviceAuthorizationAsync(new DeviceAuthorizationRequest
                {
                    Address = disco.DeviceAuthorizationEndpoint,
                    ClientId = config.OidClientId?.Trim(),
                    // The ClientCredentialStyle should probably be removed.
                    // Depending on the outcome of: https://github.com/DuendeSoftware/foss/pull/310
                    ClientCredentialStyle = ClientCredentialStyle.PostBody,
                    Scope = string.Join(" ", config.OidScopes.Prepend("openid profile"))
                }).ConfigureAwait(false);

                if (deviceResponse.IsError)
                {
                    _logger.LogError(
                        "Device authorization request failed: {Error} - {ErrorDescription}",
                        deviceResponse.Error,
                        deviceResponse.ErrorDescription);
                    return StatusCode(StatusCodes.Status400BadRequest, $"Device authorization failed");
                }

                _logger.LogInformation("Device authorization response received. User code: {UserCode}", deviceResponse.UserCode);

                // Generate random state identifier
                var state = Convert.ToBase64String(RandomNumberGenerator.GetBytes(42));

                // Validate code_challenge
                if (string.IsNullOrEmpty(request.CodeChallenge))
                {
                    return BadRequest("code_challenge is required");
                }

                // code_challenge must be base64url encoded SHA256, which is 43 characters
                if (request.CodeChallenge.Length != 43)
                {
                    return BadRequest("Invalid code_challenge length");
                }

                // Create device code state
                var deviceCodeState = new DeviceCodeState
                {
                    DeviceCode = deviceResponse.DeviceCode,
                    UserCode = deviceResponse.UserCode,
                    VerificationUri = deviceResponse.VerificationUri,
                    VerificationUriComplete = deviceResponse.VerificationUriComplete,
                    ExpiresIn = deviceResponse.ExpiresIn ?? 60,
                    Interval = deviceResponse.Interval,
                    CurrentInterval = deviceResponse.Interval,
                    LastPolled = null,
                    CachedStatus = "pending",
                    Created = DateTime.UtcNow,
                    Valid = false,
                    CodeChallenge = request.CodeChallenge
                };

                // Store in device code state manager using state as key
                DeviceCodeStateManager[state] = deviceCodeState;

                _logger.LogInformation(
                    "Device code flow initiated for provider {Provider}. State: {State}, User code: {UserCode}",
                    provider,
                    state,
                    deviceCodeState.UserCode);
                _logger.LogDebug(
                    "Stored state: {State}, Total states in manager: {Count}",
                    state,
                    DeviceCodeStateManager.Count);

                // Return device code information in JSON format instead of HTML
                return Ok(new DeviceAuthorizationResponse
                {
                    State = state,
                    UserCode = deviceCodeState.UserCode,
                    VerificationUri = deviceCodeState.VerificationUri,
                    VerificationUriComplete = deviceCodeState.VerificationUriComplete,
                    ExpiresIn = deviceCodeState.ExpiresIn,
                    Interval = deviceCodeState.Interval
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error initiating device code flow for provider {Provider}", provider);
                return StatusCode(500, $"Error initiating device code flow: {ex.Message}");
            }
        }

        return BadRequest("Provider is not enabled");
    }

    /// <summary>
    /// Polling endpoint for device code flow. Checks if user has completed authentication.
    /// </summary>
    /// <param name="provider">The name of the provider.</param>
    /// <param name="state">The state identifier to check.</param>
    /// <param name="codeChallenge">The PKCE code challenge for validation.</param>
    /// <returns>Status of the device authorization or authentication tokens.</returns>
    [HttpGet("OID/devicePoll/{provider}")]
    [Produces(MediaTypeNames.Application.Json)]
    public async Task<ActionResult> OidDevicePoll(string provider, [FromQuery] string state, [FromQuery] string codeChallenge)
    {
        _logger.LogDebug("Device code poll request for provider {Provider}, state: {State}", provider, state);

        if (string.IsNullOrEmpty(state))
        {
            _logger.LogWarning("Device code poll request missing state");
            return BadRequest(new { error = "invalid_request", error_description = "State is required" });
        }

        var configuration = SSOPlugin.Instance.Configuration;

        if (!configuration.OidConfigs.TryGetValue(provider, out var config) || config == null)
        {
            _logger.LogWarning("Device code poll for unknown provider: {Provider}", provider);
            return NotFound(new { error = "invalid_provider", error_description = "Provider does not exist" });
        }

        if (!config.DeviceAuthorizationGrantEnabled)
        {
            return Unauthorized("Device authorization grant is not enabled for this provider");
        }

        if (!DeviceCodeStateManager.TryGetValue(state, out var deviceState))
        {
            _logger.LogWarning("State not found in state manager. State: {State}", state);
            _logger.LogDebug("Current states in manager: {Count}", DeviceCodeStateManager.Count);
            return NotFound(new { error = "invalid_state", error_description = "State not found or expired" });
        }

        // Validate code_challenge (RFC 7636)
        if (string.IsNullOrEmpty(codeChallenge) || codeChallenge != deviceState.CodeChallenge)
        {
            _logger.LogWarning("Invalid code_challenge in poll request");
            return BadRequest(new
            {
                error = "invalid_request",
                error_description = "Invalid or missing code_challenge"
            });
        }

        // Check if expired
        if (DateTime.UtcNow > deviceState.Created.AddSeconds(deviceState.ExpiresIn))
        {
            DeviceCodeStateManager.Remove(state);
            return BadRequest(new { error = "expired_token", error_description = "Device code has expired" });
        }

        // Rate limiting: Check if we should poll the OAuth server based on CurrentInterval
        // This protects the OAuth server from being spammed when clients poll frequently
        if (deviceState.LastPolled.HasValue)
        {
            var timeSinceLastPoll = (DateTime.UtcNow - deviceState.LastPolled.Value).TotalSeconds;
            if (timeSinceLastPoll < deviceState.CurrentInterval)
            {
                // Too soon to poll OAuth server again, return cached status
                _logger.LogDebug(
                    "Rate limiting: returning cached status '{Status}' for device code (polled {TimeSince:F1}s ago, interval is {Interval}s)",
                    deviceState.CachedStatus,
                    timeSinceLastPoll,
                    deviceState.CurrentInterval);
                return Ok(new { status = deviceState.CachedStatus });
            }
        }

        // Update last polled timestamp before making the request
        deviceState.LastPolled = DateTime.UtcNow;

        try
        {
            using var httpClient = new HttpClient();
            var disco = await httpClient.GetDiscoveryDocumentAsync(new DiscoveryDocumentRequest
            {
                Address = config.OidEndpoint?.Trim(),
                Policy = new DiscoveryPolicy
                {
                    AdditionalEndpointBaseAddresses = { new Uri(config.OidEndpoint?.Trim()).GetLeftPart(UriPartial.Authority) },
                    ValidateEndpoints = !config.DoNotValidateEndpoints,
                    RequireHttps = !config.DisableHttps,
                    ValidateIssuerName = !config.DoNotValidateIssuerName
                }
            }).ConfigureAwait(false);

            if (disco.IsError)
            {
                _logger.LogError("Error discovering endpoints for provider {Provider}: {Error}", provider, disco.Error);
                return StatusCode(StatusCodes.Status500InternalServerError, new { error = "server_error", error_description = $"Discovery failed: {disco.Error}" });
            }

            var tokenResponse = await httpClient.RequestDeviceTokenAsync(new DeviceTokenRequest
            {
                Address = disco.TokenEndpoint,
                ClientId = config.OidClientId?.Trim(),
                ClientSecret = config.OidSecret?.Trim(),
                DeviceCode = deviceState.DeviceCode
            }).ConfigureAwait(false);

            // Check for errors
            if (tokenResponse.IsError)
            {
                var error = tokenResponse.Error;

                // authorization_pending means user hasn't completed auth yet
                if (error == "authorization_pending")
                {
                    deviceState.CachedStatus = "pending";
                    return Ok(new { status = "pending" });
                }

                // slow_down means we're polling too fast - increase interval by 5 seconds
                if (error == "slow_down")
                {
                    deviceState.CurrentInterval += 5;
                    deviceState.CachedStatus = "pending";
                    _logger.LogInformation(
                        "OAuth server requested slow_down, increased polling interval to {Interval}s for device code",
                        deviceState.CurrentInterval);
                    return Ok(new { status = "pending" });
                }

                // Any other error is terminal
                DeviceCodeStateManager.Remove(state);
                _logger.LogError(
                    "Device token request failed for provider {Provider}: {Error} - {ErrorDescription}",
                    provider,
                    tokenResponse.Error,
                    tokenResponse.ErrorDescription);
                return BadRequest(new
                {
                    error = "Authentication failed"
                });
            }

            if (!string.IsNullOrEmpty(tokenResponse.AccessToken))
            {
                // Get user claims from userinfo endpoint using IdentityModel
                JObject claims;
                try
                {
                    _logger.LogDebug("Fetching user info from: {Endpoint}", disco.UserInfoEndpoint);
                    var userInfoResponse = await httpClient.GetUserInfoAsync(new UserInfoRequest
                    {
                        Address = disco.UserInfoEndpoint,
                        Token = tokenResponse.AccessToken
                    }).ConfigureAwait(false);

                    if (userInfoResponse.IsError)
                    {
                        _logger.LogError("Failed to fetch user info: {Error}", userInfoResponse.Error);
                        DeviceCodeStateManager.Remove(state);
                        return StatusCode(500, new { error = "server_error", error_description = $"Failed to fetch user information" });
                    }

                    // Convert claims to JObject for compatibility with existing processing logic
                    claims = new JObject();
                    foreach (var claim in userInfoResponse.Claims)
                    {
                        if (claims.ContainsKey(claim.Type))
                        {
                            // Handle multiple values for same claim
                            if (claims[claim.Type] is JArray arr)
                            {
                                arr.Add(claim.Value);
                            }
                            else
                            {
                                var existingValue = claims[claim.Type].ToString();
                                claims[claim.Type] = new JArray { existingValue, claim.Value };
                            }
                        }
                        else
                        {
                            claims[claim.Type] = claim.Value;
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Failed to fetch user info for device code flow");
                    DeviceCodeStateManager.Remove(state);
                    return StatusCode(500, new { error = "server_error", error_description = "Failed to fetch user information" });
                }

                // Extract username and process roles
                var username = ExtractUsername(claims, config);
                var (isValid, isAdmin, folders, enableLiveTv, enableLiveTvManagement) = ProcessRoleClaims(claims, config);

                if (!isValid)
                {
                    DeviceCodeStateManager.Remove(state);
                    return Unauthorized(new { error = "access_denied", error_description = "User does not have required roles" });
                }

                // Update device state with user information
                deviceState.Username = username;
                deviceState.Admin = isAdmin;
                deviceState.Folders = folders;
                deviceState.EnableLiveTv = enableLiveTv;
                deviceState.EnableLiveTvManagement = enableLiveTvManagement;
                deviceState.Valid = true;

                // Handle avatar URL if configured
                if (config.AvatarUrlFormat != null)
                {
                    deviceState.AvatarURL = config.AvatarUrlFormat;
                    foreach (var claim in claims)
                    {
                        deviceState.AvatarURL = deviceState.AvatarURL.Replace($"{{{claim.Key}}}", claim.Value?.ToString() ?? string.Empty);
                    }
                }

                _logger.LogInformation("Device code flow completed for user {Username}", username);

                // Update cached status and return success
                deviceState.CachedStatus = "complete";
                return Ok(new { status = "complete" });
            }

            // if we didn't get an access token, return pending just to be safe
            deviceState.CachedStatus = "pending";
            return Ok(new { status = "pending" });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error polling device code for provider {Provider}", provider);
            return StatusCode(500, new { error = "server_error", error_description = ex.Message });
        }
    }

    /// <summary>
    /// Authentication endpoint for device code flow. Called by client after polling succeeds.
    /// </summary>
    /// <param name="provider">The name of the provider.</param>
    /// <param name="response">The client device information.</param>
    /// <returns>Authentication response with access token. <see cref="OkResult"/> containing the <see cref="AuthenticationResult"/>.</returns>
    [HttpPost("OID/deviceAuth/{provider}")]
    [Consumes(MediaTypeNames.Application.Json)]
    [Produces(MediaTypeNames.Application.Json)]
    public async Task<ActionResult> OidDeviceAuth(string provider, [FromBody] AuthResponse response)
    {
        var configuration = SSOPlugin.Instance.Configuration;

        if (!configuration.OidConfigs.TryGetValue(provider, out var config) || config == null)
        {
            return NotFound("Provider does not exist");
        }

        if (!config.DeviceAuthorizationGrantEnabled)
        {
            return Unauthorized("Device authorization grant is not enabled for this provider");
        }

        if (!DeviceCodeStateManager.TryGetValue(response.Data, out var deviceState))
        {
            return NotFound("State not found or expired");
        }

        // Check if state is older than 1 minute
        if (DateTime.UtcNow > deviceState.Created.AddMinutes(1))
        {
            DeviceCodeStateManager.Remove(response.Data);
            return BadRequest(new { error = "expired", error_description = "State has expired" });
        }

        // Validate code_verifier (RFC 7636)
        if (string.IsNullOrEmpty(response.CodeVerifier))
        {
            return BadRequest("code_verifier is required");
        }

        // code_verifier must be 43-128 characters [A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~"
        if (response.CodeVerifier.Length < 43 || response.CodeVerifier.Length > 128)
        {
            return BadRequest("Invalid code_verifier length");
        }

        // Verify code_challenge = BASE64URL(SHA256(ASCII(code_verifier)))
        using (var sha256 = SHA256.Create())
        {
            var challengeBytes = sha256.ComputeHash(System.Text.Encoding.ASCII.GetBytes(response.CodeVerifier));
            var computedChallenge = Base64UrlEncode(challengeBytes);

            if (computedChallenge != deviceState.CodeChallenge)
            {
                _logger.LogWarning("PKCE validation failed for device authorization");
                return BadRequest("Invalid code_verifier");
            }
        }

        if (!deviceState.Valid)
        {
            return BadRequest("Device code not yet authorized");
        }

        try
        {
            // Create or get user
            var userId = await CreateCanonicalLinkAndUserIfNotExist("oid", provider, deviceState.Username).ConfigureAwait(false);

            // Use the existing Authenticate helper to complete authentication
            var authResult = await Authenticate(
                userId,
                deviceState.Admin,
                config.EnableAuthorization,
                config.EnableAllFolders,
                deviceState.Folders.ToArray(),
                deviceState.EnableLiveTv,
                deviceState.EnableLiveTvManagement,
                response,
                config.DefaultProvider?.Trim(),
                deviceState.AvatarURL).ConfigureAwait(false);

            // Clean up device code state
            DeviceCodeStateManager.Remove(response.Data);

            return Ok(authResult);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error authenticating device code for provider {Provider}", provider);
            return StatusCode(500, $"Authentication error: {ex.Message}");
        }
    }

    /// <summary>
    /// Adds an OpenID auth configuration. Requires administrator privileges. If the provider already exists, it will be removed and readded.
    /// </summary>
    /// <param name="provider">The name of the provider to add.</param>
    /// <param name="config">The OID configuration (deserialized from a JSON post).</param>
    [Authorize(Policy = Policies.RequiresElevation)]
    [HttpPost("OID/Add/{provider}")]
    public void OidAdd(string provider, [FromBody] OidConfig config)
    {
        var configuration = SSOPlugin.Instance.Configuration;
        configuration.OidConfigs[provider] = config;
        SSOPlugin.Instance.UpdateConfiguration(configuration);
    }

    /// <summary>
    /// Deletes an OpenID provider.
    /// </summary>
    /// <param name="provider">Name of provider to delete.</param>
    [Authorize(Policy = Policies.RequiresElevation)]
    [HttpGet("OID/Del/{provider}")]
    public void OidDel(string provider)
    {
        var configuration = SSOPlugin.Instance.Configuration;
        configuration.OidConfigs.Remove(provider);
        SSOPlugin.Instance.UpdateConfiguration(configuration);
    }

    /// <summary>
    /// Lists the OpenID providers configured. Requires administrator privileges.
    /// </summary>
    /// <returns>The list of OpenID configurations.</returns>
    [Authorize(Policy = Policies.RequiresElevation)]
    [HttpGet("OID/Get")]
    public ActionResult OidProviders()
    {
        return Ok(SSOPlugin.Instance.Configuration.OidConfigs);
    }

    /// <summary>
    /// Lists the OpenID providers names only.
    /// </summary>
    /// <returns>The list of OpenID configurations.</returns>
    [HttpGet("OID/GetNames")]
    public ActionResult OidProviderNames()
    {
        return Ok(SSOPlugin.Instance.Configuration.OidConfigs.Keys);
    }

    /// <summary>
    /// Lists the OpenID provider names that have device authorization grant enabled.
    /// </summary>
    /// <returns>The list of OpenID provider names.</returns>
    [HttpGet("OID/GetDeviceNames")]
    public ActionResult OidDeviceProviderNames()
    {
        var deviceProviders = SSOPlugin.Instance.Configuration.OidConfigs
            .Where(kvp => kvp.Value.DeviceAuthorizationGrantEnabled)
            .Select(kvp => kvp.Key)
            .ToList();

        return Ok(deviceProviders);
    }

    /// <summary>
    /// Lists the SAML providers names only.
    /// </summary>
    /// <returns>The list of OpenID configurations.</returns>
    [HttpGet("SAML/GetNames")]
    public ActionResult SamlProviderNames()
    {
        return Ok(SSOPlugin.Instance.Configuration.SamlConfigs.Keys);
    }

    /// <summary>
    /// This is a debug endpoint to list all running OpenID flows. Requires administrator privileges.
    /// </summary>
    /// <returns>The list of OpenID flows in progress.</returns>
    [Authorize(Policy = Policies.RequiresElevation)]
    [HttpGet("OID/States")]
    public ActionResult OidStates()
    {
        return Ok(StateManager);
    }

    /// <summary>
    /// This endpoint accepts JSON and will authorize the user from the device values passed from the client.
    /// </summary>
    /// <param name="provider">Name of provider to authenticate against.</param>
    /// <param name="response">The data passed to the client to ensure it is the right one.</param>
    /// <returns>JSON for the client to populate information with.</returns>
    [HttpPost("OID/Auth/{provider}")]
    [Consumes(MediaTypeNames.Application.Json)]
    [Produces(MediaTypeNames.Application.Json)]
    public async Task<ActionResult> OidAuth(string provider, [FromBody] AuthResponse response)
    {
        OidConfig config;
        try
        {
            config = SSOPlugin.Instance.Configuration.OidConfigs[provider];
        }
        catch (KeyNotFoundException)
        {
            return BadRequest("No matching provider found");
        }

        if (config.Enabled)
        {
            foreach (var kvp in StateManager)
            {
                if (kvp.Value.State.State.Equals(response.Data) && kvp.Value.Valid)
                {
                    Guid userId = await CreateCanonicalLinkAndUserIfNotExist("oid", provider, kvp.Value.Username);

                    var authenticationResult = await Authenticate(userId, kvp.Value.Admin, config.EnableAuthorization, config.EnableAllFolders, kvp.Value.Folders.ToArray(), kvp.Value.EnableLiveTv, kvp.Value.EnableLiveTvManagement, response, config.DefaultProvider?.Trim(), kvp.Value.AvatarURL)
                        .ConfigureAwait(false);
                    return Ok(authenticationResult);
                }
            }
        }

        return Problem("Something went wrong");
    }

    /// <summary>
    /// This is the callback for the SAML flow. This creates a webpage to complete auth.
    /// </summary>
    /// <param name="provider">The provider that is calling back.</param>
    /// <param name="relayState">
    ///    RelayState given in the original saml request. If it is equal to "linking",
    ///    We consider this to be a linking request.
    /// </param>
    /// <returns>A webpage that will complete the client-side flow.</returns>
    [HttpPost("SAML/p/{provider}")]
    [HttpPost("SAML/post/{provider}")]
    public ActionResult SamlPost(string provider, [FromQuery] string relayState = null)
    {
        SamlConfig config;
        try
        {
            config = SSOPlugin.Instance.Configuration.SamlConfigs[provider];
        }
        catch (KeyNotFoundException)
        {
            return BadRequest("No matching provider found");
        }

        bool isLinking = relayState == "linking";

        _logger.LogInformation(
            $"SAML request has relayState of {relayState}");

        if (config.Enabled)
        {
            var samlResponse = new Response(config.SamlCertificate, Request.Form["SAMLResponse"]);

            bool valid = false;

            // If no roles are configured, don't use RBAC
            if (config.Roles.Length == 0)
            {
                valid = true;
            }

            // Check if user is allowed to log in based on roles
            foreach (string role in samlResponse.GetCustomAttributes("Role"))
            {
                foreach (string allowedRole in config.Roles)
                {
                    if (allowedRole.Equals(role))
                    {
                        valid = true;
                    }
                }
            }

            if (valid)
            {
                return Content(
                        WebResponse.Generator(
                            data: Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(samlResponse.Xml)),
                            provider: provider,
                            baseUrl: GetRequestBase(config.SchemeOverride, config.PortOverride),
                            mode: "SAML",
                            isLinking: isLinking),
                        MediaTypeNames.Text.Html);
            }

            _logger.LogWarning(
                "SAML user: {UserId} has insufficient roles: {@Roles}. Expected any one of: {@ExpectedRoles}",
                samlResponse.GetNameID(),
                samlResponse.GetCustomAttributes("Role"),
                config.Roles);
            return ReturnError(StatusCodes.Status401Unauthorized, "Error. Check permissions.");
        }

        return ReturnError(StatusCodes.Status400BadRequest, "No active providers found");
    }

    /// <summary>
    /// Initializes the SAML flow. This will redirect the user to the SAML provider.
    /// </summary>
    /// <param name="provider">The provider to being the flow with.</param>
    /// <param name="isLinking">Whether this flow intends to link an account, or initiate auth.</param>
    /// <returns>A redirect to the SAML provider's auth page.</returns>
    [HttpGet("SAML/p/{provider}")]
    [HttpGet("SAML/start/{provider}")]
    public RedirectResult SamlChallenge(string provider, [FromQuery] bool isLinking = false)
    {
        SamlConfig config;
        try
        {
            config = SSOPlugin.Instance.Configuration.SamlConfigs[provider];
        }
        catch (KeyNotFoundException)
        {
            throw new ArgumentException("Provider does not exist");
        }

        if (config.Enabled)
        {
            bool newPath = config.NewPath;
            if (!isLinking)
            {
                newPath = Request.Path.Value.Contains("/start/", StringComparison.InvariantCultureIgnoreCase);
                config.NewPath = newPath;
            }

            string redirectUri = GetRequestBase(config.SchemeOverride, config.PortOverride) + $"/sso/SAML/{(newPath ? "post" : "p")}/" + provider;
            string relayState = null;
            if (isLinking)
            {
                relayState = "linking";
            }

            var request = new AuthRequest(
                config.SamlClientId.Trim(),
                redirectUri);

            return Redirect(request.GetRedirectUrl(config.SamlEndpoint.Trim(), relayState));
        }

        throw new ArgumentException("Provider does not exist");
    }

    /// <summary>
    /// Adds a SAML configuration. If the provider already exists, overwrite it.
    /// </summary>
    /// <param name="provider">The provider name to add.</param>
    /// <param name="newConfig">The SAML configuration object (deserialized) from JSON.</param>
    /// <returns>The success result.</returns>
    [Authorize(Policy = Policies.RequiresElevation)]
    [HttpPost("SAML/Add/{provider}")]
    public OkResult SamlAdd(string provider, [FromBody] SamlConfig newConfig)
    {
        var configuration = SSOPlugin.Instance.Configuration;
        configuration.SamlConfigs[provider] = newConfig;
        SSOPlugin.Instance.UpdateConfiguration(configuration);
        return Ok();
    }

    /// <summary>
    /// Deletes a provider from the configuration with a given ID.
    /// </summary>
    /// <param name="provider">The ID of the provider to delete.</param>
    /// <returns>The success result.</returns>
    [Authorize(Policy = Policies.RequiresElevation)]
    [HttpGet("SAML/Del/{provider}")]
    public OkResult SamlDel(string provider)
    {
        var configuration = SSOPlugin.Instance.Configuration;
        configuration.SamlConfigs.Remove(provider);
        SSOPlugin.Instance.UpdateConfiguration(configuration);
        return Ok();
    }

    /// <summary>
    /// Returns a list of all SAML providers configured. Requires administrator privileges.
    /// </summary>
    /// <returns>A list of all of the Saml providers available.</returns>
    [Authorize(Policy = Policies.RequiresElevation)]
    [HttpGet("SAML/Get")]
    public ActionResult SamlProviders()
    {
        return Ok(SSOPlugin.Instance.Configuration.SamlConfigs);
    }

    /// <summary>
    /// This endpoint accepts JSON and will authorize the user from the device values passed from the client.
    /// </summary>
    /// <param name="provider">The provider to authenticate against.</param>
    /// <param name="response">The data passed to the client to ensure it is the right one.</param>
    /// <returns>JSON for the client to populate information with.</returns>
    [HttpPost("SAML/Auth/{provider}")]
    [Consumes(MediaTypeNames.Application.Json)]
    [Produces(MediaTypeNames.Application.Json)]
    public async Task<ActionResult> SamlAuth(string provider, [FromBody] AuthResponse response)
    {
        SamlConfig config;
        try
        {
            config = SSOPlugin.Instance.Configuration.SamlConfigs[provider];
        }
        catch (KeyNotFoundException)
        {
            return BadRequest("No matching provider found");
        }

        if (config.Enabled)
        {
            bool isAdmin = false;
            bool liveTv = config.EnableLiveTv;
            bool liveTvManagement = config.EnableLiveTvManagement;
            var samlResponse = new Response(config.SamlCertificate, response.Data);
            List<string> folders;
            if (!config.EnableFolderRoles && config.EnabledFolders != null)
            {
                folders = new List<string>(config.EnabledFolders);
            }
            else
            {
                folders = new List<string>();
            }

            foreach (string role in samlResponse.GetCustomAttributes("Role"))
            {
                if (config.AdminRoles != null)
                {
                    foreach (string allowedRole in config.AdminRoles)
                    {
                        if (allowedRole.Equals(role))
                        {
                            isAdmin = true;
                        }
                    }
                }

                if (config.EnableFolderRoles)
                {
                    if (config.FolderRoleMapping != null)
                    {
                        foreach (FolderRoleMap folderRoleMap in config.FolderRoleMapping)
                        {
                            if (folderRoleMap.Role.Equals(role))
                            {
                                folders.AddRange(folderRoleMap.Folders);
                            }
                        }
                    }
                }

                if (config.EnableLiveTvRoles)
                {
                    if (config.LiveTvRoles != null)
                    {
                        foreach (string allowedLiveTvRole in config.LiveTvRoles)
                        {
                            if (allowedLiveTvRole.Equals(role))
                            {
                                liveTv = true;
                            }
                        }
                    }

                    if (config.LiveTvManagementRoles != null)
                    {
                        foreach (string allowedLiveTvManagementRole in config.LiveTvManagementRoles)
                        {
                            if (allowedLiveTvManagementRole.Equals(role))
                            {
                                liveTvManagement = true;
                            }
                        }
                    }
                }
            }

            Guid userId = await CreateCanonicalLinkAndUserIfNotExist("saml", provider, samlResponse.GetNameID());

            var authenticationResult = await Authenticate(userId, isAdmin, config.EnableAuthorization, config.EnableAllFolders, folders.ToArray(), liveTv, liveTvManagement, response, config.DefaultProvider?.Trim(), null)
                .ConfigureAwait(false);
            return Ok(authenticationResult);
        }

        return Problem("Something went wrong");
    }

    /// <summary>
    /// Removes a user from SSO auth and switches it back to another auth provider. Requires administrator privileges.
    /// </summary>
    /// <param name="username">The username to switch to the new provider.</param>
    /// <param name="provider">The new provider to switch to.</param>
    /// <returns>Whether this API endpoint succeeded.</returns>
    [Authorize(Policy = Policies.RequiresElevation)]
    [HttpPost("Unregister/{username}")]
    public ActionResult Unregister(string username, [FromBody] string provider)
    {
        User user = _userManager.GetUserByName(username);
        user.AuthenticationProviderId = provider;

        return Ok();
    }

    private SerializableDictionary<string, Guid> GetCanonicalLinks(string mode, string provider)
    {
        SerializableDictionary<string, Guid> links = null;

        switch (mode.ToLower())
        {
            case "saml":
                links = SSOPlugin.Instance.Configuration.SamlConfigs[provider].CanonicalLinks;
                break;
            case "oid":
                links = SSOPlugin.Instance.Configuration.OidConfigs[provider].CanonicalLinks;
                break;
            default:
                throw new ArgumentException($"{mode} is not a valid choice between 'saml' and 'oid'");
        }

        if (links == null)
        {
            links = new SerializableDictionary<string, Guid>();
        }

        return links;
    }

    private async Task<Guid> CreateCanonicalLinkAndUserIfNotExist(string mode, string provider, string canonicalName)
    {
        User user = null;

        // First try to get the user by its id in case it was already registered before
        Guid userId = Guid.Empty;
        try
        {
            userId = GetCanonicalLink(mode, provider, canonicalName);
        }
        catch (KeyNotFoundException)
        {
            userId = Guid.Empty;
        }

        // No userId found? Let's try and find the user by name instead
        if (userId == Guid.Empty)
        {
            user = _userManager.GetUserByName(canonicalName);
        }
        else
        {
            user = _userManager.GetUserById(userId);
        }

        if (user == null)
        {
            _logger.LogInformation($"SSO user {canonicalName} doesn't exist, creating...");
            user = await _userManager.CreateUserAsync(canonicalName).ConfigureAwait(false);
            user.AuthenticationProviderId = GetType().FullName;
            // https://jonathancrozier.com/blog/how-to-generate-a-cryptographically-secure-random-string-in-dot-net-with-c-sharp
            user.Password = _cryptoProvider.CreatePasswordHash(Convert.ToBase64String(RandomNumberGenerator.GetBytes(64))).ToString();

            // Make sure there aren't any trailing existing links
            var links = GetCanonicalLinks(mode, provider);
            links.Remove(canonicalName);
            UpdateCanonicalLinkConfig(links, mode, provider);
        }

        userId = Guid.Empty;
        try
        {
            userId = GetCanonicalLink(mode, provider, canonicalName);
        }
        catch (KeyNotFoundException)
        {
            userId = Guid.Empty;
        }

        if (userId == Guid.Empty)
        {
            _logger.LogInformation("SSO user link doesn't exist, creating...");
            userId = user.Id;
            CreateCanonicalLink(mode, provider, userId, canonicalName);
        }

        return userId;
    }

    private Guid GetCanonicalLink(string mode, string provider, string canonicalName)
    {
        SerializableDictionary<string, Guid> links = null;
        Guid userId = Guid.Empty;

        links = GetCanonicalLinks(mode, provider);

        userId = links[canonicalName];

        return userId;
    }

    /// <summary>
    /// Create a canonical link for a given user. Must be performed by the user being changed, or admin.
    /// </summary>
    /// <param name="mode">The mode of the function; SAML or OID.</param>
    /// <param name="provider">The name of the provider to link to a jellyfin account.</param>
    /// <param name="jellyfinUserId">The user ID within jellyfin to link to the provider.</param>
    /// <param name="authResponse">The client information to authenticate the user with.</param>
    /// <returns>Whether this API endpoint succeeded.</returns>
    [Authorize]
    [HttpPost("{mode}/Link/{provider}/{jellyfinUserId}")]
    [Consumes(MediaTypeNames.Application.Json)]
    [Produces(MediaTypeNames.Application.Json)]
    public async Task<ActionResult> AddCanonicalLink([FromRoute] string mode, [FromRoute] string provider, [FromRoute] Guid jellyfinUserId, [FromBody] AuthResponse authResponse)
    {
        if (!await RequestHelpers.AssertCanUpdateUser(_authContext, HttpContext.Request, jellyfinUserId, true).ConfigureAwait(false))
        {
            return StatusCode(StatusCodes.Status403Forbidden, "User is not allowed to link SSO providers.");
        }

        switch (mode.ToLower())
        {
            case "saml":
                return SamlLink(provider, jellyfinUserId, authResponse);
            case "oid":
                return OidLink(provider, jellyfinUserId, authResponse);
            default:
                throw new ArgumentException($"{mode} is not a valid choice between 'saml' and 'oid'");
        }
    }

    /// <summary>
    /// Unregisters a given mapping from id within provider to user.
    /// </summary>
    /// <param name="mode">The mode of the function; SAML or OID.</param>
    /// <param name="provider">The name of the provider from which the link should be removed.</param>
    /// <param name="jellyfinUserId">The user ID within jellyfin to unlink from the provider.</param>
    /// <param name="canonicalName">The user ID within jellyfin to unlink.</param>
    /// <returns>Whether this API endpoint succeeded.</returns>
    [Authorize]
    [HttpDelete("{mode}/Link/{provider}/{jellyfinUserId}/{canonicalName}")]
    [Consumes(MediaTypeNames.Application.Json)]
    [Produces(MediaTypeNames.Application.Json)]
    public async Task<ActionResult> DeleteCanonicalLink([FromRoute] string mode, [FromRoute] string provider, [FromRoute] Guid jellyfinUserId, [FromRoute] string canonicalName)
    {
        if (!await RequestHelpers.AssertCanUpdateUser(_authContext, HttpContext.Request, jellyfinUserId, true).ConfigureAwait(false))
        {
            return StatusCode(StatusCodes.Status403Forbidden, "Current user is not allowed to unlink SSO providers for user ID.");
        }

        Guid linkedId = GetCanonicalLink(mode, provider, canonicalName);

        if (linkedId != jellyfinUserId)
        {
            return StatusCode(StatusCodes.Status409Conflict, "jellyfin UID does not match id registered to that canonical name.");
        }

        var links = GetCanonicalLinks(mode, provider);

        links.Remove(canonicalName);

        return UpdateCanonicalLinkConfig(links, mode, provider);
    }

    /// <summary>
    /// Gets all the saml links for a user.
    /// </summary>
    /// <param name="jellyfinUserId">The user ID within jellyfin for which to return the links.</param>
    /// <returns>A dictionary of provider : link mappings.</returns>
    [Authorize]
    [HttpGet("saml/links/{jellyfinUserId}")]
    [Produces(MediaTypeNames.Application.Json)]
    public async Task<ActionResult<SerializableDictionary<string, IEnumerable<string>>>> GetSamlLinksByUser(Guid jellyfinUserId)
    {
        if (!await RequestHelpers.AssertCanUpdateUser(_authContext, HttpContext.Request, jellyfinUserId, true).ConfigureAwait(false))
        {
            return StatusCode(StatusCodes.Status403Forbidden, "Non-admin is not allowed to query other user's mappings.");
        }

        var mappings = new SerializableDictionary<string, IEnumerable<string>>();
        var providerList = SSOPlugin.Instance.Configuration.SamlConfigs;

        foreach (var providerName in providerList.Keys)
        {
            var canonLinks = providerList[providerName].CanonicalLinks;
            var canonKeys = from link in canonLinks where link.Value == jellyfinUserId select link.Key;
            mappings[providerName] = canonKeys;
        }

        return mappings;
    }

    /// <summary>
    /// Gets all the oid links for a user.
    /// </summary>
    /// <param name="jellyfinUserId">The user ID within jellyfin for which to return the links.</param>
    /// <returns>A dictionary of provider : link mappings.</returns>
    [Authorize]
    [HttpGet("oid/links/{jellyfinUserId}")]
    [Produces(MediaTypeNames.Application.Json)]
    public async Task<ActionResult<SerializableDictionary<string, IEnumerable<string>>>> GetOidLinksByUser(Guid jellyfinUserId)
    {
        if (!await RequestHelpers.AssertCanUpdateUser(_authContext, HttpContext.Request, jellyfinUserId, true).ConfigureAwait(false))
        {
            return StatusCode(StatusCodes.Status403Forbidden, "Non-admin is not allowed to query other user's mappings.");
        }

        var mappings = new SerializableDictionary<string, IEnumerable<string>>();
        var providerList = SSOPlugin.Instance.Configuration.OidConfigs;

        foreach (var providerName in providerList.Keys)
        {
            var canonLinks = providerList[providerName].CanonicalLinks;
            var canonKeys = from link in canonLinks where link.Value == jellyfinUserId select link.Key;
            mappings[providerName] = canonKeys;
        }

        return mappings;
    }

    /// <summary>
    /// Validate a saml link request and create the link if it is valid.
    /// </summary>
    /// <param name="provider">The provider to authenticate against.</param>
    /// <param name="jellyfinUserId">
    ///   The ID of the account to be linked to the provider.
    ///   Must be performed by this user, or an admin.
    /// </param>
    /// <param name="response">The data passed to the client to ensure it is the right one.</param>
    /// <returns>JSON for the client to populate information with.</returns>
    [Consumes(MediaTypeNames.Application.Json)]
    [Produces(MediaTypeNames.Application.Json)]
    private ActionResult SamlLink(string provider, Guid jellyfinUserId, AuthResponse response)
    {
        SamlConfig config;
        try
        {
            config = SSOPlugin.Instance.Configuration.SamlConfigs[provider];
        }
        catch (KeyNotFoundException)
        {
            return BadRequest("No matching provider found");
        }

        var samlResponse = new Response(config.SamlCertificate, response.Data);
        // TODO: Does saml response require further validation?

        string providerUserId = samlResponse.GetNameID();

        return CreateCanonicalLink("saml", provider, jellyfinUserId, providerUserId);
    }

    /// <summary>
    /// Validate an OIDC link request and create the link if it is valid.
    /// </summary>
    /// <param name="provider">The provider to authenticate against.</param>
    /// <param name="jellyfinUserId">
    ///   The ID of the account to be linked to the provider.
    ///   Must be performed by this user, or an admin.
    /// </param>
    /// <param name="response">The data passed to the client to ensure it is the right one.</param>
    /// <returns>JSON for the client to populate information with.</returns>
    [Consumes(MediaTypeNames.Application.Json)]
    [Produces(MediaTypeNames.Application.Json)]
    private ActionResult OidLink(string provider, Guid jellyfinUserId, AuthResponse response)
    {
        OidConfig config;
        try
        {
            config = SSOPlugin.Instance.Configuration.OidConfigs[provider];
        }
        catch (KeyNotFoundException)
        {
            return BadRequest("No matching provider found");
        }

        foreach (var kvp in StateManager)
        {
            if (kvp.Value.State.State.Equals(response.Data) && kvp.Value.Valid)
            {
                string providerUserId = kvp.Value.Username;
                return CreateCanonicalLink("oid", provider, jellyfinUserId, providerUserId);
            }
        }

        return Problem("Something went wrong!");
    }

    private ActionResult CreateCanonicalLink(string mode, string provider, [FromRoute] Guid jellyfinUserId, string providerUserId)
    {
        SerializableDictionary<string, Guid> links = null;
        try
        {
            links = GetCanonicalLinks(mode, provider);
        }
        catch (KeyNotFoundException)
        {
            return BadRequest("No matching provider found");
        }

        links[providerUserId] = jellyfinUserId;
        UpdateCanonicalLinkConfig(links, mode, provider);

        return NoContent();
    }

    private OkResult UpdateCanonicalLinkConfig(SerializableDictionary<string, Guid> links, string mode, string provider)
    {
        var configuration = SSOPlugin.Instance.Configuration;
        switch (mode.ToLower())
        {
            case "saml":
                configuration.SamlConfigs[provider].CanonicalLinks = links;
                break;
            case "oid":
                configuration.OidConfigs[provider].CanonicalLinks = links;
                break;
            default:
                throw new ArgumentException($"{mode} is not a valid choice between 'saml' and 'oid'");
        }

        SSOPlugin.Instance.UpdateConfiguration(configuration);
        return Ok();
    }

    /// <summary>
    /// Authenticates the user with the given information.
    /// </summary>
    /// <param name="userId">The user id of the user to authenticate.</param>
    /// <param name="isAdmin">Determines whether this user is an administrator.</param>
    /// <param name="enableAuthorization">Determines whether RBAC is used for this user.</param>
    /// <param name="enableAllFolders">Determines whether all folders are enabled.</param>
    /// <param name="enabledFolders">Determines which folders should be enabled for this client.</param>
    /// <param name="enableLiveTv">Determines whether live TV access is allowed for this user.</param>
    /// <param name="enableLiveTvAdmin">Determines whether live TV can be managed by this user.</param>
    /// <param name="authResponse">The client information to authenticate the user with.</param>
    /// <param name="defaultProvider">The default provider of the user to be set after logging in.</param>
    /// <param name="avatarUrl">The new avatar url for the user.</param>
    private async Task<AuthenticationResult> Authenticate(Guid userId, bool isAdmin, bool enableAuthorization, bool enableAllFolders, string[] enabledFolders, bool enableLiveTv, bool enableLiveTvAdmin, AuthResponse authResponse, string defaultProvider, string avatarUrl)
    {
        User user = _userManager.GetUserById(userId);
        if (enableAuthorization)
        {
            user.SetPermission(PermissionKind.IsAdministrator, isAdmin);
            user.SetPermission(PermissionKind.EnableAllFolders, enableAllFolders);
            if (!enableAllFolders)
            {
                user.SetPreference(PreferenceKind.EnabledFolders, enabledFolders);
            }
        }

        if (avatarUrl is not null)
        {
            try
            {
                using var client = new HttpClient();
                var avatarResponse = await client.GetAsync(avatarUrl);

                if (!avatarResponse.Content.Headers.TryGetValues("content-type", out var contentTypeList))
                {
                    throw new Exception("Cannot get Content-Type of image : " + avatarUrl);
                }

                var contentType = contentTypeList.First();
                if (!contentType.StartsWith("image"))
                {
                    throw new Exception("Content type of avatar URL is not an image, got :  " + contentType);
                }

                var extension = contentType.Split("/").Last();
                var stream = await avatarResponse.Content.ReadAsStreamAsync();

                if (user != null)
                {
                    var userDataPath =
                        Path.Combine(
                            _serverConfigurationManager.ApplicationPaths.UserConfigurationDirectoryPath,
                            user.Username);
                    if (user.ProfileImage is not null)
                    {
                        await _userManager.ClearProfileImageAsync(user).ConfigureAwait(false);
                    }

                    user.ProfileImage = new ImageInfo(Path.Combine(userDataPath, "profile" + extension));

                    await _providerManager.SaveImage(stream, contentType, user.ProfileImage.Path)
                        .ConfigureAwait(false);
                }
            }
            catch (Exception e)
            {
                _logger.LogError(e.Message);
            }
        }

        user.SetPermission(PermissionKind.EnableLiveTvAccess, enableLiveTv);
        user.SetPermission(PermissionKind.EnableLiveTvManagement, enableLiveTvAdmin);

        await _userManager.UpdateUserAsync(user).ConfigureAwait(false);

        var authRequest = new AuthenticationRequest();
        authRequest.UserId = user.Id;
        authRequest.Username = user.Username;
        authRequest.App = authResponse.AppName;
        authRequest.AppVersion = authResponse.AppVersion;
        authRequest.DeviceId = authResponse.DeviceID;
        authRequest.DeviceName = authResponse.DeviceName;
        _logger.LogInformation("Auth request created...");
        if (!string.IsNullOrEmpty(defaultProvider))
        {
            user.AuthenticationProviderId = defaultProvider;
            await _userManager.UpdateUserAsync(user).ConfigureAwait(false);
            _logger.LogInformation("Set default login provider to " + defaultProvider);
        }

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

    private string GetRequestBase(string schemeOverride = null, int? portOverride = null)
    {
        int requestPort;

        if (portOverride != null)
        {
            requestPort = portOverride.Value;
        }
        else
        {
            requestPort = Request.Host.Port ?? -1;
        }

        if ((requestPort == 80 && string.Equals(Request.Scheme, "http", StringComparison.OrdinalIgnoreCase)) || (requestPort == 443 && string.Equals(Request.Scheme, "https", StringComparison.OrdinalIgnoreCase)))
        {
            requestPort = -1;
        }

        if (schemeOverride != "http" && schemeOverride != "https")
        {
            schemeOverride = null;
        }

        return new UriBuilder
        {
            Scheme = schemeOverride ?? Request.Scheme,
            Host = Request.Host.Host,
            Port = requestPort,
            Path = Request.PathBase
        }.ToString().TrimEnd('/');
    }

    private ContentResult ReturnError(int code, string message)
    {
        var errorResult = new ContentResult();
        errorResult.Content = message;
        errorResult.ContentType = MediaTypeNames.Text.Plain;
        errorResult.StatusCode = code;
        return errorResult;
    }

    /// <summary>
    /// Base64url encode (RFC 7636 Section 4.2).
    /// </summary>
    /// <param name="data">The data to encode.</param>
    /// <returns>Base64url encoded string.</returns>
    private static string Base64UrlEncode(byte[] data)
    {
        var base64 = Convert.ToBase64String(data);
        // Replace URL-unsafe characters and remove padding
        return base64.Replace("+", "-").Replace("/", "_").Replace("=", string.Empty);
    }
}

/// <summary>
/// The data the client should pass back to the API.
/// </summary>
public class AuthResponse
{
    /// <summary>
    /// Gets or sets the device ID of the client.
    /// </summary>
    public string DeviceID { get; set; }

    /// <summary>
    /// Gets or sets the device name of the client.
    /// </summary>
    public string DeviceName { get; set; }

    /// <summary>
    /// Gets or sets the app name of the client.
    /// </summary>
    public string AppName { get; set; }

    /// <summary>
    /// Gets or sets the app version of the client.
    /// </summary>
    public string AppVersion { get; set; }

    /// <summary>
    /// Gets or sets the auth data of the client (for authorizing the response).
    /// </summary>
    public string Data { get; set; }

    /// <summary>
    /// Gets or sets the PKCE code verifier for device authorization flow.
    /// </summary>
    public string CodeVerifier { get; set; }
}

/// <summary>
/// Device authorization request payload for PKCE.
/// </summary>
public class DeviceAuthRequest
{
    /// <summary>
    /// Gets or sets the PKCE code challenge.
    /// </summary>
    public string CodeChallenge { get; set; }
}

/// <summary>
/// Device authorization response containing device code flow information.
/// </summary>
public class DeviceAuthorizationResponse
{
    /// <summary>
    /// Gets or sets the state identifier for tracking this authorization.
    /// </summary>
    public string State { get; set; }

    /// <summary>
    /// Gets or sets the user code to display to the user.
    /// </summary>
    public string UserCode { get; set; }

    /// <summary>
    /// Gets or sets the verification URI where the user should authenticate.
    /// </summary>
    public string VerificationUri { get; set; }

    /// <summary>
    /// Gets or sets the complete verification URI with user code pre-filled.
    /// </summary>
    public string VerificationUriComplete { get; set; }

    /// <summary>
    /// Gets or sets the number of seconds until the device code expires.
    /// </summary>
    public int ExpiresIn { get; set; }

    /// <summary>
    /// Gets or sets the minimum polling interval in seconds.
    /// </summary>
    public int Interval { get; set; }
}

/// <summary>
/// Base class for authorization states containing common user information.
/// </summary>
public abstract class AuthorizeStateBase
{
    /// <summary>
    /// Gets or sets when this object was created.
    /// </summary>
    public DateTime Created { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether the user is valid.
    /// </summary>
    public bool Valid { get; set; }

    /// <summary>
    /// Gets or sets the user tied to the state.
    /// </summary>
    public string Username { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether the user is an administrator.
    /// </summary>
    public bool Admin { get; set; }

    /// <summary>
    /// Gets or sets the folders the user is allowed access to.
    /// </summary>
    public List<string> Folders { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether the user is allowed to view live TV.
    /// </summary>
    public bool EnableLiveTv { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether the user is allowed to manage live TV.
    /// </summary>
    public bool EnableLiveTvManagement { get; set; }

    /// <summary>
    /// Gets or sets the user avatar url.
    /// </summary>
    public string AvatarURL { get; set; }
}

/// <summary>
/// A manager for OpenID to manage the state of the clients.
/// </summary>
public class TimedAuthorizeState : AuthorizeStateBase
{
    /// <summary>
    /// Initializes a new instance of the <see cref="TimedAuthorizeState"/> class.
    /// </summary>
    /// <param name="state">The AuthorizeState to time.</param>
    /// <param name="created">When this state was created.</param>
    public TimedAuthorizeState(AuthorizeState state, DateTime created)
    {
        State = state;
        Created = created;
        Valid = false;
        Admin = false;
        IsLinking = false;
        EnableLiveTv = false;
        EnableLiveTvManagement = false;
        AvatarURL = null;
    }

    /// <summary>
    /// Gets or sets the Authorization State of the client.
    /// </summary>
    public AuthorizeState State { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether the state is
    /// tied to a linking flow (instead of a login flow).
    /// </summary>
    public bool IsLinking { get; set; }
}

/// <summary>
/// A manager for device code flow to track device authorization states.
/// </summary>
public class DeviceCodeState : AuthorizeStateBase
{
    /// <summary>
    /// Gets or sets the device code returned from the authorization endpoint.
    /// </summary>
    public string DeviceCode { get; set; }

    /// <summary>
    /// Gets or sets the user code to display to the user.
    /// </summary>
    public string UserCode { get; set; }

    /// <summary>
    /// Gets or sets the verification URI where the user should authenticate.
    /// </summary>
    public string VerificationUri { get; set; }

    /// <summary>
    /// Gets or sets the verification URI with the user code already embedded.
    /// </summary>
    public string VerificationUriComplete { get; set; }

    /// <summary>
    /// Gets or sets the expiration time in seconds.
    /// </summary>
    public int ExpiresIn { get; set; }

    /// <summary>
    /// Gets or sets the polling interval in seconds.
    /// </summary>
    public int Interval { get; set; }

    /// <summary>
    /// Gets or sets the current polling interval (may be increased due to slow_down).
    /// </summary>
    public int CurrentInterval { get; set; }

    /// <summary>
    /// Gets or sets the last time we polled the OAuth server for this device code.
    /// </summary>
    public DateTime? LastPolled { get; set; }

    /// <summary>
    /// Gets or sets the cached polling status to return to clients without hitting OAuth server.
    /// </summary>
    public string CachedStatus { get; set; }

    /// <summary>
    /// Gets or sets the PKCE code challenge.
    /// </summary>
    public string CodeChallenge { get; set; }
}
