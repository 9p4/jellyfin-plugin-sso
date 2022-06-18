using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Mime;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using IdentityModel.OidcClient;
using Jellyfin.Data.Entities;
using Jellyfin.Data.Enums;
using Jellyfin.Plugin.SSO_Auth;
using Jellyfin.Plugin.SSO_Auth.Config;
using Jellyfin.Plugin.SSO_Auth.Helpers;
using MediaBrowser.Controller.Authentication;
using MediaBrowser.Controller.Library;
using MediaBrowser.Controller.Net;
using MediaBrowser.Controller.Session;
using MediaBrowser.Model;
using MediaBrowser.Model.Plugins;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ViewEngines;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace Jellyfin.Plugin.SSO_Auth.Views;

/// <summary>
/// The sso views controller.
/// </summary>
[ApiController]
[Route("[controller]")]
public class SSOViewsController : ControllerBase
{
    private readonly IUserManager _userManager;
    private readonly ISessionManager _sessionManager;
    private readonly IAuthorizationContext _authContext;
    private readonly ILogger<SSOViewsController> _logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="SSOViewsController"/> class.
    /// </summary>
    /// <param name="logger">Instance of the <see cref="ILogger{SSOViewsController}"/> interface.</param>
    /// <param name="sessionManager">Instance of the <see cref="ISessionManager"/> interface.</param>
    /// <param name="authContext">Instance of the <see cref="IAuthorizationContext"/> interface.</param>
    /// <param name="userManager">Instance of the <see cref="IUserManager"/> interface.</param>
    public SSOViewsController(ILogger<SSOViewsController> logger, ISessionManager sessionManager, IUserManager userManager, IAuthorizationContext authContext)
    {
        _sessionManager = sessionManager;
        _userManager = userManager;
        _authContext = authContext;
        _logger = logger;
        _logger.LogInformation("SSO Views Controller initialized");
    }

    private ActionResult ServeView(string viewName)
    {
        IEnumerable<PluginPageInfo> pages = null;
        if (SSOPlugin.Instance == null)
        {
            return BadRequest("No plugin instance found");
        }

        pages = SSOPlugin.Instance.GetViews();

        if (pages == null)
        {
            return NotFound("Pages is null or empty");
        }

        var view = pages.FirstOrDefault(pageInfo => pageInfo.Name == viewName, null);

        if (view == null)
        {
            return NotFound("No matching view found");
        }
#nullable enable
        Stream? stream = SSOPlugin.Instance.GetType().Assembly.GetManifestResourceStream(view.EmbeddedResourcePath);

        if (stream == null)
        {
            _logger.LogError("Failed to get resource {Resource}", view.EmbeddedResourcePath);
            return NotFound();
        }
#nullable disable
        return File(stream, MimeTypes.GetMimeType(view.EmbeddedResourcePath));
    }

    /// <summary>
    /// Gets the html view for the linking interface.
    /// </summary>
    /// <returns>The html view for the linking interface.</returns>
    // [Authorize(Policy = "DefaultAuthorization")]
    [HttpGet("linking")]
    public ActionResult GetLinkingView()
    {
        return ServeView("SSO-Auth-linking");
    }

    /// <summary>
    /// Returns the client code for the linking view.
    /// </summary>
    /// <returns>The html view for the linking interface.</returns>
    // [Authorize(Policy = "DefaultAuthorization")]
    [HttpGet("linking.js")]
    public ActionResult GetLinkingJS()
    {
        return ServeView("SSO-Auth-linking.js");
    }

    /// <summary>
    /// Returns the shared js module that initializes the ApiClient.
    /// </summary>
    /// <returns>The html view for the linking interface.</returns>
    // [Authorize(Policy = "DefaultAuthorization")]
    [HttpGet("ApiClient.js")]
    public ActionResult GetApiClientView()
    {
        return ServeView("SSO-Auth-ApiClient.js");
    }
}