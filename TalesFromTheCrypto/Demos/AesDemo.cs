namespace TalesFromTheCrypto.Demos
{
    using System;
    using System.IO;
    using System.Security.Cryptography;
    using System.Text;
    using Inf;

    public class AesDemo : ICryptoDemo
    {
        /// <summary>
        /// Encrypts the specified input string using the key provided.
        /// </summary>
        /// <param name="input">The input.</param>
        /// <param name="keyBytes">The key bytes.</param>
        /// <returns></returns>
        public string Encrypt(string input, byte[] keyBytes)
        {
            using (var aes = new AesCryptoServiceProvider
            {
                Key = keyBytes,
                Mode = CipherMode.CBC,
                Padding = PaddingMode.PKCS7
            })
            {

                var inputBytes = Encoding.UTF8.GetBytes(input);
                aes.GenerateIV();
                var iv = aes.IV;
                using (var encrypter = aes.CreateEncryptor(aes.Key, iv))
                using (var cipherStream = new MemoryStream())
                {
                    using (var tCryptoStream = new CryptoStream(cipherStream, encrypter, CryptoStreamMode.Write))
                    using (var tBinaryWriter = new BinaryWriter(tCryptoStream))
                    {
                        //Prepend IV to data
                        //tBinaryWriter.Write(iv); This is the original broken code, it encrypts the iv
                        cipherStream.Write(iv, 0, 16);  // Write iv to the plain stream (not tested though)
                        tBinaryWriter.Write(inputBytes);
                        tCryptoStream.FlushFinalBlock();
                    }

                    return Convert.ToBase64String(cipherStream.ToArray());
                }
            }
        }

        /// <summary>
        /// Decrypts the specified input string using the key provided.
        /// </summary>
        /// <param name="input">The input.</param>
        /// <param name="keyBytes">The key bytes.</param>
        /// <returns></returns>
        public string Decrypt(string input, byte[] keyBytes)
        {
            using (var provider = new AesCryptoServiceProvider())
            {
                var s = Convert.FromBase64String(input);
                provider.Key = keyBytes;

                using (var ms = new MemoryStream(s))
                {
                    // Read the first 16 bytes which is the IV.
                    byte[] iv = new byte[16];
                    ms.Read(iv, 0, 16);
                    provider.IV = iv;

                    using (var decryptor = provider.CreateDecryptor())
                    {
                        using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                        {
                            using (var sr = new StreamReader(cs))
                            {
                                return sr.ReadToEnd();
                            }
                        }
                    }
                }
            }
        }
    }
}
