using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;

namespace JWT.Api.Services
{
    public class JwtService : IJwtService
    {
        public string GenerateToken()
        {
            //chave simétrica
            //var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtConfig.SecretKey));

            //chave assimétrica RSA
            //var rsa = RSA.Create();
            //string privateXmlKey = File.ReadAllText("./private_key.xml");
            //rsa.FromXmlString(privateXmlKey);
            //var key = new RsaSecurityKey(rsa);

            //chave assimétrica ECDsa
            //1
            //var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            //string privateXmlKey = File.ReadAllText("./private_ec_key.xml");
            //ecdsa.FromXmlString(privateXmlKey);
            //var key = new ECDsaSecurityKey(ecdsa);
            //2
            ////string keyFile = "./private_ec.pem";
            ////var secret = File.ReadAllText(keyFile);
            //var secret = "MHcCAQEEIMwk+VFL1zikNI5ywx3oM1+csRpbAMZBjrBlRaqPD1cGoAoGCCqGSM49\r\nAwEHoUQDQgAEkEwPfTUQTI+3CsBv+X3sWYIh3q1ykfN7oojtROBWbXIWQ6QH8HHU\r\nWot3KZ6BSs0GHc4YizjLcCu0yi9KY93+vQ==";
            //var ecdsa = ECDsa.Create();
            //ecdsa.ImportECPrivateKey(Convert.FromBase64String(secret), out _);
            //var key = new ECDsaSecurityKey(ecdsa);
            //2.1 - método acima tb funciona (mas não funcionou para importar chave pública)
            //var eccPem = File.ReadAllText("C:\\Users\\adqt3535\\OneDrive - ADIQ Soluções de Pagamento S A\\Documentos\\AdiqFlavio\\Chaves Ingenico - JWT\\private-qa.pem");
            var eccPem = File.ReadAllText("private_ec_key.pem");
            var ecdsa = ECDsa.Create();
            ecdsa.ImportFromPem(eccPem);
            var key = new ECDsaSecurityKey(ecdsa);

            var tokenExpiration = DateTime.UtcNow.AddSeconds(60);
            var claims = new List<Claim>
            {

            };

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Issuer = "issuer",
                Audience = "audience",
                Expires = tokenExpiration,
                //SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256Signature)
                //SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.RsaSha256)
                SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.EcdsaSha256),
                //Claims = claims.To
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            var securityToken = tokenHandler.CreateToken(tokenDescriptor);

            return tokenHandler.WriteToken(securityToken);
        }

        public string ValidateToken(string token)
        {
            try
            {
                var tokenHandler = new JwtSecurityTokenHandler();

                //chave simétrica
                //var key = Encoding.ASCII.GetBytes("ZmxhdmlvZmxhdmlvZmxhdmlvZmxhdmlvZmxhdmlv");

                //chae assimétrica RSA
                //var rsa = RSA.Create();
                //string publicXmlKey = File.ReadAllText("./public_key.xml");
                //publicXmlKey = File.ReadAllText("./public_ec_key.xml");
                //rsa.FromXmlString(publicXmlKey);
                //var key = new RsaSecurityKey(rsa);

                //chave assimétrica ECDsa
                //1
                //var secret = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEkEwPfTUQTI+3CsBv+X3sWYIh3q1y\r\nkfN7oojtROBWbXIWQ6QH8HHUWot3KZ6BSs0GHc4YizjLcCu0yi9KY93+vQ==";
                //var ecdsa = ECDsa.Create();
                //ecdsa.ImportECPrivateKey(Convert.FromBase64String(secret), out _);
                //var key = new ECDsaSecurityKey(ecdsa);
                //2
                //var eccPem = File.ReadAllText("C:\\Users\\adqt3535\\OneDrive - ADIQ Soluções de Pagamento S A\\Documentos\\AdiqFlavio\\Chaves Ingenico - JWT\\public-qa.pem");
                var eccPem = File.ReadAllText("public_ec_key.pem");
                var ecdsa = ECDsa.Create();
                ecdsa.ImportFromPem(eccPem);
                var key = new ECDsaSecurityKey(ecdsa);

                tokenHandler.ValidateToken(token, new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    //IssuerSigningKey = new SymmetricSecurityKey(key),
                    IssuerSigningKey = key,
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    //ValidAudience = "",
                    //ValidIssuer = "",
                    ClockSkew = TimeSpan.Zero
                }, out SecurityToken validatedToken);

                return "Token válido";
            }
            catch (Exception ex)
            {
                return ex.Message;
            }
        }
    }

    public interface IJwtService
    {
        string GenerateToken();
        string ValidateToken(string token);
    }
}
