namespace TalesFromTheCrypto.Crypto
{
    using System.Collections.Generic;

    public interface ICryptoGenerator
    {
        /// <summary>
        /// Gets the name of the crypto type supported.
        /// </summary>
        string CryptoName { get; }

        /// <summary>
        /// Gets the text describing the crypto algorithm.
        /// </summary>
        string CryptoDescription { get; }

        /// <summary>
        /// Gets or sets the encryption key.
        /// </summary>
        byte[] Key { get; set; }

        /// <summary>
        /// Gets the current crypto mode.
        /// </summary>
        /// <value>
        /// The mode.
        /// </value>
        string Mode { get; }

        /// <summary>
        /// Gets the padding mode.
        /// </summary>
        /// <value>
        /// The padding.
        /// </value>
        string Padding { get; }
        
        /// <summary>
        /// Gets or sets the initialisation vector.
        /// </summary>
        byte[] InitialisationVector { get; set; }

        /// <summary>
        /// Gets the valid key size options for the crytography method.
        /// </summary>
        IList<int> KeySizeOptions { get; }

        /// <summary>
        /// Gets the minimum size of the legal crypto key size.
        /// </summary>
        int MinKeySize { get; }

        /// <summary>
        /// Gets the maximum size of the legal crypto key size.
        /// </summary>
        int MaxKeySize { get; }

        /// <summary>
        /// Gets the size of the legal key interval step size between the minimum and maximum key sizes.
        /// </summary>
        int KeyStepSize { get; }

        /// <summary>
        /// Gets the size of the currently selected keysize.
        /// </summary>
        /// <value>
        /// The size of the current key.
        /// </value>
        int? CurrentKeySize { get; }

        /// <summary>
        /// Initialises the crypto class instance.
        /// </summary>
        void Initialise();

        /// <summary>
        /// Calculates the valid key size options.
        /// </summary>
        /// <returns></returns>
        IList<int> CalculateKeySizeOptions();

        /// <summary>
        /// Gets the available crypto modes.
        /// </summary>
        /// <value>
        /// The available modes.
        /// </value>
        IList<string> AvailableModes { get; }

        /// <summary>
        /// Gets the available padding modes.
        /// </summary>
        /// <value>
        /// The available padding modes.
        /// </value>
        IList<string> AvailablePaddingModes { get; }

        /// <summary>
        /// Sets the size of the key.
        /// </summary>
        /// <param name="keySize">Size of the key.</param>
        void SetKeySize(int keySize);

        /// <summary>
        /// Sets the cipher mode.
        /// </summary>
        /// <param name="mode">The mode.</param>
        void SetCipherMode(string mode);

        /// <summary>
        /// Sets the padding mode.
        /// </summary>
        /// <param name="mode">The mode.</param>
        void SetPaddingMode(string mode);

        /// <summary>
        /// Generates the key byte array.
        /// </summary>
        /// <returns>a new byte[]</returns>
        byte[] GenerateKey();

        /// <summary>
        /// Generates the vector byte array.
        /// </summary>
        /// <returns>a new byte[]</returns>
        byte[] GenerateVector();

        /// <summary>
        /// Encrypts the specified string value.
        /// </summary>
        /// <param name="value">The original string value.</param>
        /// <returns>the string value in encrypted form</returns>
        string Encrypt(string value);

        /// <summary>
        /// Encrypts the specified byte array buffer.
        /// </summary>
        /// <param name="buffer">The original byte[] buffer.</param>
        /// <returns>the byte array buffer in encrypted form</returns>
        byte[] Encrypt(byte[] buffer);

        /// <summary>
        /// Decrypts the specified string value.
        /// </summary>
        /// <param name="value">The string value.</param>
        /// <returns>the string value in unencrypted form</returns>
        string Decrypt(string value);

        /// <summary>
        /// Decrypts the specified byte array buffer.
        /// </summary>
        /// <param name="buffer">The buffer.</param>
        /// <returns>the byte array byte[] buffer in unencrypted form</returns>
        byte[] Decrypt(byte[] buffer);
    }
}