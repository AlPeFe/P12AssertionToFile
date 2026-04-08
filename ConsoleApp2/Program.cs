using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;

string p12Path = @"c:\temp\p12.p12";
string outputPath = @"c:\temp\assertion.txt";
string p12Password = "pwd";  // Cambia aquí la contraseña si el .p12 la tiene

Console.WriteLine("Cargando certificado...");
var cert = new X509Certificate2(p12Path, p12Password, X509KeyStorageFlags.Exportable);

string assertionId = "_" + Guid.NewGuid().ToString("N");
string issueInstant = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");
string notBefore = DateTime.UtcNow.AddMinutes(-5).ToString("yyyy-MM-ddTHH:mm:ssZ");
string notOnOrAfter = DateTime.UtcNow.AddHours(1).ToString("yyyy-MM-ddTHH:mm:ssZ");

string samlXml = $"""
    <?xml version="1.0" encoding="UTF-8"?>
    <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
        ID="{assertionId}"
        Version="2.0"
        IssueInstant="{issueInstant}">
      <saml:Issuer>http://example.com/issuer</saml:Issuer>
      <saml:Subject>
        <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">user@example.com</saml:NameID>
        <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
          <saml:SubjectConfirmationData NotOnOrAfter="{notOnOrAfter}" Recipient="http://example.com/acs"/>
        </saml:SubjectConfirmation>
      </saml:Subject>
      <saml:Conditions NotBefore="{notBefore}" NotOnOrAfter="{notOnOrAfter}">
        <saml:AudienceRestriction>
          <saml:Audience>http://example.com/audience</saml:Audience>
        </saml:AudienceRestriction>
      </saml:Conditions>
      <saml:AuthnStatement AuthnInstant="{issueInstant}">
        <saml:AuthnContext>
          <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>
        </saml:AuthnContext>
      </saml:AuthnStatement>
    </saml:Assertion>
    """;

var xmlDoc = new XmlDocument { PreserveWhitespace = true };
xmlDoc.LoadXml(samlXml);

var signedXml = new SignedXml(xmlDoc)
{
    SigningKey = cert.GetRSAPrivateKey()
};

var reference = new Reference { Uri = "#" + assertionId };
reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
reference.AddTransform(new XmlDsigC14NTransform());
signedXml.AddReference(reference);

var keyInfo = new KeyInfo();
keyInfo.AddClause(new KeyInfoX509Data(cert));
signedXml.KeyInfo = keyInfo;

signedXml.ComputeSignature();

var signatureElement = signedXml.GetXml();
var issuerNode = xmlDoc.GetElementsByTagName("saml:Issuer")[0]!;
issuerNode.ParentNode!.InsertAfter(xmlDoc.ImportNode(signatureElement, true), issuerNode);

File.WriteAllText(outputPath, xmlDoc.OuterXml, Encoding.UTF8);

Console.WriteLine($"Assertion SAML generado y guardado en: {outputPath}");
