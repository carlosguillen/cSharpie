using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;
using System.Text;

namespace JWTz
{
    public class TokedUser
    {
        public string username { get; private set; }
        public long userId { get; private set; }
        public DateTime expiration { get; private set; }
        public string role { get; private set; }
        public int facilityId { get; private set; }

        public TokedUser (string username, long userId, DateTime expiration, string role, int facilityId)
        {
            this.username = username;
            this.userId = userId;
            this.expiration = expiration;
            this.role = role;
            this.facilityId = facilityId;
        }
    }

    public class Tokenizer
    {
        private string issuer;

        public Tokenizer(string issuer)
        {
            this.issuer = issuer;
        }

        public string decode(string privateSecreString, string token)
        {
            string payload = null;

            var signingCredentials = getSigned(privateSecreString);

            var securityTokenDescriptor = new SecurityTokenDescriptor()
            {               
                SigningCredentials = signingCredentials
            };

            var validationParameters = new TokenValidationParameters
            {                
                RequireExpirationTime = true,
                IssuerSigningKey = signingCredentials.Key,
                RequireSignedTokens = true,
                ValidateAudience = false,
                ValidateIssuer = false,
                ValidateActor = false,
                ValidateIssuerSigningKey = true,
               // ValidateSignature = false, // this feature should be fixed
                ValidateLifetime = true,
            };
            try
            {
                var handler = new JwtSecurityTokenHandler();

                SecurityToken secToken;
                handler.ValidateToken(token, validationParameters, out secToken);                
                payload = (secToken.ToString());                
            }
            catch
            {
                Console.WriteLine("Token validation failed");
            }

            return payload;            
        }

        public string encode(string privateSecreString, TokedUser user)
        {

            var signingCredentials = getSigned(privateSecreString);

            var issuedAt = DateTime.UtcNow;

            var claimsIdentity = new ClaimsIdentity(new List<Claim>()
            {
                new Claim("username", user.username),
                new Claim("facilityId", user.facilityId.ToString()),
                new Claim("userid", user.userId.ToString()),
                new Claim(ClaimTypes.Role, user.role)
            }, "Custom");

            var securityTokenDescriptor = new SecurityTokenDescriptor()
            {
                IssuedAt = DateTime.UtcNow,
                Subject = claimsIdentity,
                SigningCredentials = signingCredentials,
                Issuer = issuer,
                Expires = user.expiration
            };

            var handler = new JwtSecurityTokenHandler();            
            var jwt = handler.CreateEncodedJwt(securityTokenDescriptor);          
            return jwt;
        }
        
        private SigningCredentials getSigned (string privateSecreString)
        {
            HMACSHA256 hmac = new HMACSHA256((Encoding.UTF8.GetBytes(privateSecreString)));

            var signingKey = new SymmetricSecurityKey(hmac.Key);
            var signingCredentials = new SigningCredentials(signingKey, SecurityAlgorithms.HmacSha256);

            return signingCredentials;
        }
    }
}
