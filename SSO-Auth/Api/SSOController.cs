using System.IO;
using System.Net.Mime;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Jellyfin.Plugin.SSO_Auth.Api {
    /// <summary>
    /// The sso api controller.
    /// </summary>
    [ApiController]
    [Route("[controller]")]
    public class SSOController : ControllerBase {
      [HttpPost("SAMLPost")]
      [ProducesResponseType(StatusCodes.Status200OK)]
      [ProducesResponseType(StatusCodes.Status400BadRequest)]
      public IActionResult SAMLPost() {
        StreamReader reader = new StreamReader(Request.Body);
        string text = reader.ReadToEndAsync().Result;
        var configuration  = SSOPlugin.Instance.Configuration;
        Saml.Response samlResponse = new Saml.Response(configuration.SamlCertificate, text);
        return Ok(samlResponse);
      }

      [HttpGet("test")]
      [ProducesResponseType(StatusCodes.Status200OK)]
      public string[] test() {
        return new string[] {
          SSOPlugin.Instance.Configuration.SamlCertificate,
            SSOPlugin.Instance.Configuration.SamlEndpoint
        };
      }

      // https://stackoverflow.com/a/17535912
      [HttpPost("testPost")]
      [ProducesResponseType(StatusCodes.Status200OK)]
      [Produces(MediaTypeNames.Application.Json)]
      public string testPost() {
        StreamReader reader = new StreamReader(Request.Body);
        string text = reader.ReadToEndAsync().Result;
        return text;
      }
    }
}
