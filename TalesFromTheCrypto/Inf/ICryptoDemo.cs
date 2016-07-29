namespace TalesFromTheCrypto.Inf
{
    public interface ICryptoDemo
    {
        /// <summary>
        /// Encrypts the specified input string using the key provided.
        /// </summary>
        /// <param name="input">The input.</param>
        /// <param name="keyBytes">The key bytes.</param>
        /// <returns></returns>
        string Encrypt(string input, byte[] keyBytes);

        /// <summary>
        /// Decrypts the specified input string using the key provided.
        /// </summary>
        /// <param name="input">The input.</param>
        /// <param name="keyBytes">The key bytes.</param>
        /// <returns></returns>
        string Decrypt(string input, byte[] keyBytes);
    }
}