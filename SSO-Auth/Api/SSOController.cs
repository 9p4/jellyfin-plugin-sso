using System.IO;
using System.Net.Mime;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Saml;

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
      public string SAMLPost() {
        var configuration  = SSOPlugin.Instance.Configuration;
        Saml.Response samlResponse = new Saml.Response(configuration.SamlCertificate, Request.Form["SAMLResponse"]);
        return samlResponse.GetNameID();
      }

      [HttpGet("SAMLChallenge")]
      [ProducesResponseType(StatusCodes.Status200OK)]
      [ProducesResponseType(StatusCodes.Status400BadRequest)]
      public RedirectResult SAMLChallenge() {
        var request = new AuthRequest(
            "jellyfin-localhost",
            "http://localhost:8096/sso/SAMLPost"
            );
        return Redirect(request.GetRedirectUrl(SSOPlugin.Instance.Configuration.SamlEndpoint));
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
