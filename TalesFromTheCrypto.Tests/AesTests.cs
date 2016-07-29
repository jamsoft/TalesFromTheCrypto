namespace TalesFromTheCrypto.Tests
{
    using Demos;
    using Xunit;

    public class AesTests
    {
        private readonly byte[] _keyBytes = { 217, 131, 66, 89, 78, 63, 133, 221, 74, 77, 14, 15, 30, 180, 185, 18, 248, 98, 206, 187, 181, 22, 150, 152, 96, 42, 114, 28, 64, 188, 151, 72 };

        /// <summary>
        /// Runs the encrpt and decrypt and confirms basic behaviour.
        /// </summary>
        [Fact]
        public void RunEncrptAndDecrypt()
        {
            var aesDemo = new AesDemo();

            var originalString = "This is the original string";
            var encryptedString = aesDemo.Encrypt(originalString, _keyBytes);

            Assert.NotEmpty(encryptedString);
            Assert.NotEqual(originalString, encryptedString);

            var decryptedString = aesDemo.Decrypt(encryptedString, _keyBytes);

            Assert.Equal(originalString, decryptedString);
        }

        /// <summary>
        /// Ensures that each encrypted value is unique when given the same input string (uses a new IV each time).
        /// </summary>
        [Fact]
        public void EncryptionsAreUnique()
        {
            var aesDemo = new AesDemo();

            var originalString = "This is the original string";

            var encryptedString1 = aesDemo.Encrypt(originalString, _keyBytes);
            var encryptedString2 = aesDemo.Encrypt(originalString, _keyBytes);

            Assert.NotEqual(encryptedString1, encryptedString2);

            var decryptedString1 = aesDemo.Decrypt(encryptedString1, _keyBytes);
            var decryptedString2 = aesDemo.Decrypt(encryptedString2, _keyBytes);

            Assert.Equal(originalString, decryptedString1);
            Assert.Equal(originalString, decryptedString2);
        }
    }
}