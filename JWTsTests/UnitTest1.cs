using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using JWTz;

namespace JWTsTests
{
    

    [TestClass]
    public class TokenizerTest
    {
        string username;
        long userId = 101010101;       
        string role;
        string[] roles = new string[]{ "PAX", "CREW" };
        Random rnd = new Random();
        int facilityId = 10016;

        [TestInitialize]
        public void TestInitialize()
        {
            username = Faker.Internet.Email();                        
            role = roles[rnd.Next(roles.Length)];
        }

        [TestMethod]
        public void encodeTest()
        {
            TokedUser user = new TokedUser(username, userId, DateTime.UtcNow.AddDays(2), role, facilityId);
            var mySecret = "this is my rifle";
            Tokenizer tokenizer = new Tokenizer("ICS");
            
            var jwt = tokenizer.encode(mySecret, user);
            var sections = jwt.Split('.');
            
            Assert.AreEqual(sections.Length, 3);
        }

        [TestMethod]
        public void decodeTest()
        {
            TokedUser user = new TokedUser(username, userId, DateTime.UtcNow.AddDays(2), role, facilityId);
            var mySecret = "this is my rifle";
            Tokenizer tokenizer = new Tokenizer("ICS");

            var jwt = tokenizer.encode(mySecret, user);
            var sections = jwt.Split('.');

            Assert.AreEqual(sections.Length, 3);

            var decoded = tokenizer.decode(mySecret, jwt);

            //TODO: this should be test each claim individually
            Assert.AreEqual(decoded.Contains(role), true);
            Assert.AreEqual(decoded.Contains(username), true);
            Assert.AreEqual(decoded.Contains(facilityId.ToString()), true);
        }

        [TestMethod]
        public void decodeFailedTest()
        {
            TokedUser user = new TokedUser(username, userId, DateTime.UtcNow.AddDays(2), role, facilityId);
            var mySecret = "this is my rifle";
            Tokenizer tokenizer = new Tokenizer("ICS");

            var jwt = tokenizer.encode(mySecret, user);
            var sections = jwt.Split('.');

            Assert.AreEqual(sections.Length, 3);

            var decoded = tokenizer.decode("not a valid secret", jwt);

            Assert.AreEqual(decoded, null);
        }
    }
}
