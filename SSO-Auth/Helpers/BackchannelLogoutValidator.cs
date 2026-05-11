using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Jellyfin.Plugin.SSO_Auth.Config;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace Jellyfin.Plugin.SSO_Auth.Helpers;

/// <summary>
/// Validates OIDC Back-Channel Logout tokens per
/// <see href="https://openid.net/specs/openid-connect-backchannel-1_0.html">OpenID Connect Back-Channel Logout 1.0</see>,
/// section 2.6.
/// </summary>
public sealed class BackchannelLogoutValidator
{
    private const string LogoutEventUri = "http://schemas.openid.net/event/backchannel-logout";

    private static readonly MemoryCache _discoveryCache = new(new MemoryCacheOptions());
    private static readonly MemoryCache _jtiReplayCache = new(new MemoryCacheOptions());
    private static readonly TimeSpan _discoveryTtl = TimeSpan.FromHours(12);
    private static readonly TimeSpan _jtiTtl = TimeSpan.FromMinutes(30);
    private static readonly TimeSpan _maxIatFutureSkew = TimeSpan.FromMinutes(5);

    private readonly ILogger _logger;
    private readonly IHttpClientFactory _httpClientFactory;

    /// <summary>
    /// Initializes a new instance of the <see cref="BackchannelLogoutValidator"/> class.
    /// </summary>
    /// <param name="logger">Logger for diagnostic messages.</param>
    /// <param name="httpClientFactory">Factory used to fetch discovery and JWKS documents.</param>
    public BackchannelLogoutValidator(ILogger logger, IHttpClientFactory httpClientFactory)
    {
        _logger = logger;
        _httpClientFactory = httpClientFactory;
    }

    /// <summary>
    /// Validates a logout token against the configured provider.
    /// </summary>
    /// <param name="logoutToken">The JWT supplied in the <c>logout_token</c> form field.</param>
    /// <param name="config">The matching <see cref="OidConfig"/> for the provider.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A <see cref="BackchannelLogoutTokenResult"/> with the relevant claim values.</returns>
    /// <exception cref="BackchannelLogoutException">If validation fails for any reason.</exception>
    public async Task<BackchannelLogoutTokenResult> ValidateAsync(
        string logoutToken,
        OidConfig config,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(logoutToken))
        {
            throw new BackchannelLogoutException("logout_token is missing");
        }

        var configuration = await GetOpenIdConfigurationAsync(config, cancellationToken).ConfigureAwait(false);

        var validationParameters = new TokenValidationParameters
        {
            ValidateIssuer = !config.DoNotValidateIssuerName,
            ValidIssuer = configuration.Issuer,
            ValidateAudience = true,
            ValidAudience = config.OidClientId?.Trim(),
            ValidateLifetime = false,
            RequireExpirationTime = false,
            RequireSignedTokens = true,
            ValidateIssuerSigningKey = true,
            IssuerSigningKeys = configuration.SigningKeys,
        };

        var handler = new JsonWebTokenHandler();
        var validationResult = await handler.ValidateTokenAsync(logoutToken, validationParameters).ConfigureAwait(false);
        if (!validationResult.IsValid)
        {
            throw new BackchannelLogoutException(
                "Token signature or basic claim validation failed: " + (validationResult.Exception?.Message ?? "unknown"),
                validationResult.Exception);
        }

        var jwt = (JsonWebToken)validationResult.SecurityToken;

        if (jwt.TryGetPayloadValue<string>("nonce", out _))
        {
            throw new BackchannelLogoutException("nonce claim MUST NOT be present in a logout token");
        }

        if (!jwt.TryGetPayloadValue<string>("jti", out var jti) || string.IsNullOrEmpty(jti))
        {
            throw new BackchannelLogoutException("jti claim is required");
        }

        var replayKey = (configuration.Issuer ?? string.Empty) + " " + jti;
        if (!_jtiReplayCache.TryGetValue(replayKey, out _))
        {
            _jtiReplayCache.Set(replayKey, true, _jtiTtl);
        }
        else
        {
            throw new BackchannelLogoutException("jti replay detected");
        }

        if (jwt.TryGetPayloadValue<long>("iat", out var iat))
        {
            var iatTime = DateTimeOffset.FromUnixTimeSeconds(iat);
            if (iatTime > DateTimeOffset.UtcNow.Add(_maxIatFutureSkew))
            {
                throw new BackchannelLogoutException("iat is too far in the future");
            }
        }

        ValidateEventsClaim(jwt);

        var sub = jwt.TryGetPayloadValue<string>("sub", out var subValue) ? subValue : null;
        var sid = jwt.TryGetPayloadValue<string>("sid", out var sidValue) ? sidValue : null;

        if (string.IsNullOrEmpty(sub) && string.IsNullOrEmpty(sid))
        {
            throw new BackchannelLogoutException("logout token must include sub and/or sid");
        }

        return new BackchannelLogoutTokenResult(sub, sid, jti);
    }

    private static void ValidateEventsClaim(JsonWebToken jwt)
    {
        if (!jwt.TryGetPayloadValue<JsonElement>("events", out var eventsElement))
        {
            throw new BackchannelLogoutException("events claim is required");
        }

        if (eventsElement.ValueKind != JsonValueKind.Object)
        {
            throw new BackchannelLogoutException("events claim must be a JSON object");
        }

        if (!eventsElement.TryGetProperty(LogoutEventUri, out _))
        {
            throw new BackchannelLogoutException(
                "events claim must contain " + LogoutEventUri);
        }
    }

    private async Task<OpenIdConnectConfiguration> GetOpenIdConfigurationAsync(
        OidConfig config,
        CancellationToken cancellationToken)
    {
        var authority = config.OidEndpoint?.Trim();
        if (string.IsNullOrEmpty(authority))
        {
            throw new BackchannelLogoutException("Provider has no OID endpoint configured");
        }

        if (_discoveryCache.TryGetValue(authority, out OpenIdConnectConfiguration cached))
        {
            return cached;
        }

        var metadataAddress = authority.TrimEnd('/') + "/.well-known/openid-configuration";

        var httpClient = _httpClientFactory.CreateClient();
        var documentRetriever = new HttpDocumentRetriever(httpClient)
        {
            RequireHttps = !config.DisableHttps,
        };

        var manager = new ConfigurationManager<OpenIdConnectConfiguration>(
            metadataAddress,
            new OpenIdConnectConfigurationRetriever(),
            documentRetriever);

        OpenIdConnectConfiguration configuration;
        try
        {
            configuration = await manager.GetConfigurationAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            throw new BackchannelLogoutException(
                "Failed to retrieve OpenID configuration from " + metadataAddress + ": " + ex.Message,
                ex);
        }

        _discoveryCache.Set(authority, configuration, _discoveryTtl);
        return configuration;
    }
}

/// <summary>
/// Result of a successful logout-token validation.
/// </summary>
/// <param name="Sub">The <c>sub</c> claim value, if present.</param>
/// <param name="Sid">The <c>sid</c> claim value, if present.</param>
/// <param name="Jti">The unique <c>jti</c> claim value.</param>
public sealed record BackchannelLogoutTokenResult(string Sub, string Sid, string Jti);

/// <summary>
/// Thrown when a back-channel logout token cannot be validated.
/// </summary>
public sealed class BackchannelLogoutException : Exception
{
    /// <summary>
    /// Initializes a new instance of the <see cref="BackchannelLogoutException"/> class.
    /// </summary>
    /// <param name="message">The error message.</param>
    public BackchannelLogoutException(string message)
        : base(message)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="BackchannelLogoutException"/> class.
    /// </summary>
    /// <param name="message">The error message.</param>
    /// <param name="innerException">The wrapped exception.</param>
    public BackchannelLogoutException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
