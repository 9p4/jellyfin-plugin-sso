using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Mime;
using MediaBrowser.Common;
using MediaBrowser.Controller.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Jellyfin.Plugin.SSO_Auth.Api {
    /// <summary>
    /// The sso api controller.
    /// </summary>
    [ApiController]
    [Authorize(Policy = "RequiresElevation")]
    [Route("[controller]")]
    [Produces(MediaTypeNames.Application.Json)]
    public class SSOController : ControllerBase {
      [HttpPost("SAMLPost")]
      [ProducesResponseType(StatusCodes.Status200OK)]
      [ProducesResponseType(StatusCodes.Status400BadRequest)]
      public IActionResult SAMLPost(string response) {
        var configuration  = SSOPlugin.Instance.Configuration;
        Saml.Response samlResponse = new Saml.Response(configuration.SamlCertificate, response);
        return Ok(samlResponse);
      }
    }
}
