/*
 Was Jitbit's simple SAML 2.0 component for ASP.NET
 https://github.com/jitbit/AspNetSaml/
 (c) Jitbit LP, 2016
 Use this freely under the Apache license (see https://choosealicense.com/licenses/apache-2.0/)
 version 1.2.3
*/

using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Web;
using System.Xml;

namespace Jellyfin.Plugin.SSO_Auth;

/// <summary>
/// Represents a SAML response.
/// </summary>
public class Response
{
    private readonly X509Certificate2 _certificate;
    private XmlDocument _xmlDoc;
    private XmlNamespaceManager _xmlNameSpaceManager; // we need this one to run our XPath queries on the SAML XML

    /// <summary>
    /// Initializes a new instance of the <see cref="Response"/> class.
    /// </summary>
    /// <param name="certificateStr">The certificate formatted as a Base64 string.</param>
    /// <param name="responseString">The SAML response formatted as a string.</param>
    public Response(string certificateStr, string responseString)
        : this(Convert.FromBase64String(certificateStr), responseString)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="Response"/> class.
    /// </summary>
    /// <param name="certificateBytes">The certificate formatted as an array of bytes.</param>
    /// <param name="responseString">The SAML response formatted as a string.</param>
    public Response(byte[] certificateBytes, string responseString) : this(certificateBytes)
    {
        LoadXmlFromBase64(responseString);
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="Response"/> class.
    /// </summary>
    /// <param name="certificateStr">The certificate formatted as a Base64 string.</param>
    public Response(string certificateStr) : this(Convert.FromBase64String(certificateStr))
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="Response"/> class.
    /// </summary>
    /// <param name="certificateBytes">The certificate formatted as an array of bytes.</param>
    public Response(byte[] certificateBytes)
    {
        _certificate = new X509Certificate2(certificateBytes);
    }

    /// <summary>
    /// Gets the SAML response's XML data.
    /// </summary>
    public string Xml => _xmlDoc.OuterXml;

    /// <summary>
    /// Loads XML from the parameter into the instance's XML data.
    /// </summary>
    /// <param name="xml">The XML string to put into the class.</param>
    public void LoadXml(string xml)
    {
        _xmlDoc = new XmlDocument();
        _xmlDoc.PreserveWhitespace = true;
        _xmlDoc.XmlResolver = null;
        _xmlDoc.LoadXml(xml);

        _xmlNameSpaceManager = GetNamespaceManager(); // lets construct a "manager" for XPath queries
    }

    /// <summary>
    /// Loads Base64 encoded XML from the parameter into the instance's XML data.
    /// </summary>
    /// <param name="response">The Base64 encoded XML string to put into the class.</param>
    public void LoadXmlFromBase64(string response)
    {
        LoadXml(Encoding.UTF8.GetString(Convert.FromBase64String(response)));
    }

    /// <summary>
    /// Checks whether the XML response is valid by verifying the signature.
    /// </summary>
    /// <returns>Whether the XML response is valid.</returns>
    public bool IsValid()
    {
        var nodeList = _xmlDoc.SelectNodes("//ds:Signature", _xmlNameSpaceManager);

        var signedXml = new SignedXml(_xmlDoc);

        if (nodeList.Count == 0)
        {
            return false;
        }

        signedXml.LoadXml((XmlElement)nodeList[0]);
        return ValidateSignatureReference(signedXml) && signedXml.CheckSignature(_certificate, true) && !IsExpired();
    }

    // an XML signature can "cover" not the whole document, but only a part of it
    // .NET's built in "CheckSignature" does not cover this case, it will validate to true.
    // We should check the signature reference, so it "references" the id of the root document element! If not - it's a hack
    private bool ValidateSignatureReference(SignedXml signedXml)
    {
        if (signedXml.SignedInfo.References.Count != 1) // no ref at all
        {
            return false;
        }

        var reference = (Reference)signedXml.SignedInfo.References[0];
        var id = reference.Uri.Substring(1);

        var idElement = signedXml.GetIdElement(_xmlDoc, id);

        if (idElement == _xmlDoc.DocumentElement)
        {
            return true;
        }
        else // sometimes its not the "root" doc-element that is being signed, but the "assertion" element
        {
            var assertionNode = _xmlDoc.SelectSingleNode("/samlp:Response/saml:Assertion", _xmlNameSpaceManager) as XmlElement;
            if (assertionNode != idElement)
            {
                return false;
            }
        }

        return true;
    }

    private bool IsExpired()
    {
        var expirationDate = DateTime.MaxValue;
        var node = _xmlDoc.SelectSingleNode("/samlp:Response/saml:Assertion[1]/saml:Subject/saml:SubjectConfirmation/saml:SubjectConfirmationData", _xmlNameSpaceManager);
        if (node != null && node.Attributes["NotOnOrAfter"] != null)
        {
            DateTime.TryParse(node.Attributes["NotOnOrAfter"].Value, out expirationDate);
        }

        return DateTime.UtcNow > expirationDate.ToUniversalTime();
    }

    /// <summary>
    /// Gets the name ID attribute from the XML response.
    /// </summary>
    /// <returns>The name ID attribute.</returns>
    public string GetNameID()
    {
        var node = _xmlDoc.SelectSingleNode("/samlp:Response/saml:Assertion[1]/saml:Subject/saml:NameID", _xmlNameSpaceManager);
        return node.InnerText;
    }

    /// <summary>
    /// Gets the UPN attribute from the XML response.
    /// </summary>
    /// <returns>The UPN attribute.</returns>
    public virtual string GetUpn()
    {
        return GetCustomAttribute("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn");
    }

    /// <summary>
    /// Gets the email attribute from the XML response.
    /// </summary>
    /// <returns>The email attribute.</returns>
    public virtual string GetEmail()
    {
        return GetCustomAttribute("User.email")
               // some providers (for example Azure AD) put last name into an attribute named "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"
               ?? GetCustomAttribute("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress")
               // some providers put last name into an attribute named "mail"
               ?? GetCustomAttribute("mail");
    }

    /// <summary>
    /// Gets the First Name attribute from the XML response.
    /// </summary>
    /// <returns>The First Name attribute.</returns>
    public virtual string GetFirstName()
    {
        return GetCustomAttribute("first_name")
               // some providers (for example Azure AD) put last name into an attribute named "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname"
               ?? GetCustomAttribute("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname")
               ?? GetCustomAttribute("User.FirstName")
               // some providers put last name into an attribute named "givenName"
               ?? GetCustomAttribute("givenName");
    }

    /// <summary>
    /// Gets the Last Name attribute from the XML response.
    /// </summary>
    /// <returns>The Last Name attribute.</returns>
    public virtual string GetLastName()
    {
        return GetCustomAttribute("last_name")
               // some providers (for example Azure AD) put last name into an attribute named "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname"
               ?? GetCustomAttribute("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname")
               ?? GetCustomAttribute("User.LastName")
               // some providers put last name into an attribute named "sn"
               ?? GetCustomAttribute("sn");
    }

    /// <summary>
    /// Gets the department attribute from the XML response.
    /// </summary>
    /// <returns>The department attribute.</returns>
    public virtual string GetDepartment()
    {
        return GetCustomAttribute("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/department")
               ?? GetCustomAttribute("department");
    }

    /// <summary>
    /// Gets the phone attribute from the XML response.
    /// </summary>
    /// <returns>The phone attribute.</returns>
    public virtual string GetPhone()
    {
        return GetCustomAttribute("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/homephone")
               ?? GetCustomAttribute("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/telephonenumber");
    }

    /// <summary>
    /// Gets the company attribute from the XML response.
    /// </summary>
    /// <returns>The company attribute.</returns>
    public virtual string GetCompany()
    {
        return GetCustomAttribute("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/companyname")
               ?? GetCustomAttribute("organization")
               ?? GetCustomAttribute("User.CompanyName");
    }

    /// <summary>
    /// Gets the location attribute from the XML response.
    /// </summary>
    /// <returns>The location attribute.</returns>
    public virtual string GetLocation()
    {
        return GetCustomAttribute("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/location")
               ?? GetCustomAttribute("physicalDeliveryOfficeName");
    }

    /// <summary>
    /// Gets the first custom attribute from the XML response.
    /// </summary>
    /// <param name="attr">The custom attribute to query.</param>
    /// <returns>The custom attribute.</returns>
    public string GetCustomAttribute(string attr)
    {
        var node = _xmlDoc.SelectSingleNode("/samlp:Response/saml:Assertion[1]/saml:AttributeStatement/saml:Attribute[@Name='" + attr + "']/saml:AttributeValue", _xmlNameSpaceManager);
        return node?.InnerText;
    }

    /// <summary>
    /// Gets the values for a custom attribute from the XML response.
    /// </summary>
    /// <param name="attr">The custom attribute to query.</param>
    /// <returns>The custom attributes.</returns>
    public List<string> GetCustomAttributes(string attr)
    {
        var node = _xmlDoc.SelectNodes("/samlp:Response/saml:Assertion[1]/saml:AttributeStatement/saml:Attribute[@Name='" + attr + "']/saml:AttributeValue", _xmlNameSpaceManager);
        List<string> output = new List<string>();
        foreach (XmlNode item in node)
        {
            output.Add(item?.InnerText);
        }

        return output;
    }

    // returns namespace manager, we need one b/c MS says so... Otherwise XPath doesnt work in an XML doc with namespaces
    // see https://stackoverflow.com/questions/7178111/why-is-xmlnamespacemanager-necessary
    private XmlNamespaceManager GetNamespaceManager()
    {
        var manager = new XmlNamespaceManager(_xmlDoc.NameTable);
        manager.AddNamespace("ds", SignedXml.XmlDsigNamespaceUrl);
        manager.AddNamespace("saml", "urn:oasis:names:tc:SAML:2.0:assertion");
        manager.AddNamespace("samlp", "urn:oasis:names:tc:SAML:2.0:protocol");

        return manager;
    }
}

/// <summary>
/// Represents a SAML request.
/// </summary>
public class AuthRequest
{
    private readonly string _id;
    private readonly string _issueInstant;

    private readonly string _issuer;
    private readonly string _assertionConsumerServiceUrl;

    /// <summary>
    /// Initializes a new instance of the <see cref="AuthRequest"/> class..
    /// </summary>
    /// <param name="issuer">The issuer of the SAML request.</param>
    /// <param name="assertionConsumerServiceUrl">The SAML assertion URL.</param>
    public AuthRequest(string issuer, string assertionConsumerServiceUrl)
    {
        _id = "_" + Guid.NewGuid().ToString();
        _issueInstant = DateTime.Now.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ", System.Globalization.CultureInfo.InvariantCulture);

        _issuer = issuer;
        _assertionConsumerServiceUrl = assertionConsumerServiceUrl;
    }

    /// <summary>
    /// The formatting of the AuthRequest.
    /// </summary>
    public enum AuthRequestFormat
    {
        /// <summary>
        /// Base64 request.
        /// </summary>
        Base64 = 1
    }

    /// <summary>
    /// Gets the SAML request.
    /// </summary>
    /// <param name="format">The format the request should be returned in.</param>
    /// <returns>The request as a string, either Base64 or not, depending on the format parameter.</returns>
    public string GetRequest(AuthRequestFormat format)
    {
        using var sw = new StringWriter();
        var xws = new XmlWriterSettings();
        xws.OmitXmlDeclaration = true;

        using (var xw = XmlWriter.Create(sw, xws))
        {
            xw.WriteStartElement("samlp", "AuthnRequest", "urn:oasis:names:tc:SAML:2.0:protocol");
            xw.WriteAttributeString("ID", _id);
            xw.WriteAttributeString("Version", "2.0");
            xw.WriteAttributeString("IssueInstant", _issueInstant);
            xw.WriteAttributeString("ProtocolBinding", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");
            xw.WriteAttributeString("AssertionConsumerServiceURL", _assertionConsumerServiceUrl);

            xw.WriteStartElement("saml", "Issuer", "urn:oasis:names:tc:SAML:2.0:assertion");
            xw.WriteString(_issuer);
            xw.WriteEndElement();

            xw.WriteStartElement("samlp", "NameIDPolicy", "urn:oasis:names:tc:SAML:2.0:protocol");
            xw.WriteAttributeString("Format", "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified");
            xw.WriteAttributeString("AllowCreate", "true");
            xw.WriteEndElement();

            /*
                xw.WriteStartElement("samlp", "RequestedAuthnContext", "urn:oasis:names:tc:SAML:2.0:protocol");
                xw.WriteAttributeString("Comparison", "exact");
                xw.WriteStartElement("saml", "AuthnContextClassRef", "urn:oasis:names:tc:SAML:2.0:assertion");
                xw.WriteString("urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport");
                xw.WriteEndElement();
                xw.WriteEndElement();
                */

            xw.WriteEndElement();
        }

        if (format == AuthRequestFormat.Base64)
        {
            // byte[] toEncodeAsBytes = System.Text.ASCIIEncoding.ASCII.GetBytes(sw.ToString());
            // return System.Convert.ToBase64String(toEncodeAsBytes);

            // https://stackoverflow.com/questions/25120025/acs75005-the-request-is-not-a-valid-saml2-protocol-message-is-showing-always%3C/a%3E
            var memoryStream = new MemoryStream();
            var writer = new StreamWriter(new DeflateStream(memoryStream, CompressionMode.Compress, true), new UTF8Encoding(false));
            writer.Write(sw.ToString());
            writer.Close();
            var result = Convert.ToBase64String(memoryStream.GetBuffer(), 0, (int)memoryStream.Length, Base64FormattingOptions.None);
            return result;
        }

        return null;
    }

    /// <summary>
    /// Gets the the URL you should redirect your users to (i.e. your SAML-provider login URL with the Base64-ed request in the querystring.
    /// </summary>
    /// <param name="samlEndpoint">The SAML endpoint.</param>
    /// <param name="relayState">The relay state.</param>
    /// <returns>The redirect url.</returns>
    public string GetRedirectUrl(string samlEndpoint, string relayState = null)
    {
        var queryStringSeparator = samlEndpoint.Contains('?') ? "&" : "?";

        var url = samlEndpoint + queryStringSeparator + "SAMLRequest=" + HttpUtility.UrlEncode(GetRequest(AuthRequestFormat.Base64));

        if (!string.IsNullOrEmpty(relayState))
        {
            url += "&RelayState=" + HttpUtility.UrlEncode(relayState);
        }

        return url;
    }
}
