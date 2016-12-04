using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;
using System.Text;

namespace JWTz
{
    class Program
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="args"></param>
        static void Main(string[] args)
        {

            var me = "carlitos_way@test.com";
            var userId = 1212121212;
            var expiration = DateTime.UtcNow.AddDays(2);
            var role = "PAX";
            var facilityId = 10016;

            var mySecret = "this is my rifle";

            TokedUser user = new TokedUser(me, userId, expiration, role, facilityId);
            Tokenizer tokenizer = new Tokenizer("ICS");
            
            var jwt = tokenizer.encode(mySecret, user);
            System.Console.WriteLine(jwt);

            var decoded = tokenizer.decode("no", jwt);
            if (decoded == null)
            {
                System.Console.WriteLine("Failed to validate token");
            }
            else
            {
                Console.WriteLine(decoded);
            }
            System.Console.ReadLine();
        }
    }


}
