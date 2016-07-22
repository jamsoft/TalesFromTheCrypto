namespace TalesFromTheCrypto.Crypto
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Security.Cryptography;
    using System.Text;

    /// <summary>
    /// See http://stackoverflow.com/questions/165808/simple-two-way-encryption-for-c-sharp
    /// </summary>
    /// <seealso cref="ICryptoGenerator" />
    public class AesCrypto : ICryptoGenerator
    {
        private ICryptoTransform _encryptor, _decryptor;
        private UTF8Encoding _encoder;
        private readonly RijndaelManaged _rijndaelManaged;

        public AesCrypto()
        {
            _rijndaelManaged = new RijndaelManaged();

            CryptoName = "AES (RijndaelManaged)";
            CryptoDescription = "The Advanced Encryption Standard (AES), also known as Rijndael (its original name), is a specification for the encryption of electronic data established by the U.S. National Institute of Standards and Technology (NIST) in 2001.  Considered a replacement DES";
        }

        public string CryptoName { get; }

        public string CryptoDescription { get; }

        /// <summary>
        /// Gets the size of the currently selected keysize.
        /// </summary>
        /// <value>
        /// The size of the current key.
        /// </value>
        public int? CurrentKeySize
        {
            get { return _rijndaelManaged?.KeySize; }
        }

        public void Initialise()
        {
            GenerateKey();
            GenerateVector();

            _encryptor = _rijndaelManaged.CreateEncryptor(Key, InitialisationVector);
            _decryptor = _rijndaelManaged.CreateDecryptor(Key, InitialisationVector);
            _encoder = new UTF8Encoding();
        }

        public byte[] Key { get; set; }

        public string Mode
        {
            get { return _rijndaelManaged.Mode.ToString(); }
        }

        public string Padding
        {
            get { return _rijndaelManaged.Padding.ToString(); }
        }

        public byte[] InitialisationVector { get; set; }

        /// <summary>
        /// Gets the valid key size options for the crytography method.
        /// </summary>
        /// <value>
        /// The key size options.
        /// </value>
        public IList<int> KeySizeOptions
        {
            get
            {
                return CalculateKeySizeOptions();
            }
        }

        /// <summary>
        /// Gets the minimum size of the legal crypto key size.
        /// </summary>
        public int MinKeySize { get; private set; }

        /// <summary>
        /// Gets the maximum size of the legal crypto key size.
        /// </summary>
        public int MaxKeySize { get; private set; }

        /// <summary>
        /// Gets the size of the legal key interval step size between the minimum and maximum key sizes.
        /// </summary>
        public int KeyStepSize { get; private set; }

        /// <summary>
        /// Gets the available padding modes.
        /// </summary>
        /// <value>
        /// The available padding modes.
        /// </value>
        public IList<string> AvailablePaddingModes
        {
            get
            {
                var opt = new List<string>(Enum.GetNames(_rijndaelManaged.Padding.GetType()));
                return opt;
            }
        }

        /// <summary>
        /// Gets the available crypto modes.
        /// </summary>
        /// <value>
        /// The available modes.
        /// </value>
        public IList<string> AvailableModes
        {
            get
            {
                var opt = new List<string>(Enum.GetNames(_rijndaelManaged.Mode.GetType()));

                // RijndaelManaged does not support these
                opt.Remove("CTS");
                opt.Remove("OFB");
                return opt;
            }
        }

        /// <summary>
        /// Sets the size of the key.
        /// </summary>
        public void SetKeySize(int keySize)
        {
            _rijndaelManaged.KeySize = keySize;
        }

        /// <summary>
        /// Sets the cipher mode.
        /// </summary>
        /// <param name="mode">The mode.</param>
        public void SetCipherMode(string mode)
        {
            _rijndaelManaged.Mode = (CipherMode)Enum.Parse(typeof(CipherMode), mode);
        }

        /// <summary>
        /// Sets the padding mode.
        /// </summary>
        /// <param name="mode">The mode.</param>
        public void SetPaddingMode(string mode)
        {
            _rijndaelManaged.Padding = (PaddingMode) Enum.Parse(typeof(PaddingMode), mode);
        }

        /// <summary>
        /// Generates the key byte array.
        /// </summary>
        /// <returns>
        /// a new byte[]
        /// </returns>
        public byte[] GenerateKey()
        {
            _rijndaelManaged.GenerateKey();
            Key = _rijndaelManaged.Key;
            return Key;
        }

        /// <summary>
        /// Generates the vector byte array.
        /// </summary>
        /// <returns>
        /// a new byte[]
        /// </returns>
        public byte[] GenerateVector()
        {
            _rijndaelManaged.GenerateIV();
            InitialisationVector = _rijndaelManaged.IV;
            return InitialisationVector;
        }

        /// <summary>
        /// Encrypts the specified string value.
        /// </summary>
        /// <param name="value">The original string value.</param>
        /// <returns>
        /// the string value in encrypted form
        /// </returns>
        public string Encrypt(string value)
        {
            return Convert.ToBase64String(Encrypt(_encoder.GetBytes(value)));
        }

        /// <summary>
        /// Decrypts the specified string value.
        /// </summary>
        /// <param name="value">The string value.</param>
        /// <returns>
        /// the string value in unencrypted form
        /// </returns>
        public string Decrypt(string value)
        {
            return _encoder.GetString(Decrypt(Convert.FromBase64String(value)));
        }

        /// <summary>
        /// Encrypts the specified byte array buffer.
        /// </summary>
        /// <param name="buffer">The original byte[] buffer.</param>
        /// <returns>
        /// the byte array buffer in encrypted form
        /// </returns>
        public byte[] Encrypt(byte[] buffer)
        {
            return Transform(buffer, _encryptor);
        }

        /// <summary>
        /// Decrypts the specified byte array buffer.
        /// </summary>
        /// <param name="buffer">The buffer.</param>
        /// <returns>
        /// the byte array byte[] buffer in unencrypted form
        /// </returns>
        public byte[] Decrypt(byte[] buffer)
        {
            return Transform(buffer, _decryptor);
        }

        /// <summary>
        /// Transforms the specified buffer.
        /// </summary>
        /// <param name="buffer">The buffer.</param>
        /// <param name="transform">The transform.</param>
        /// <returns></returns>
        protected byte[] Transform(byte[] buffer, ICryptoTransform transform)
        {
            MemoryStream stream = new MemoryStream();
            using (CryptoStream cs = new CryptoStream(stream, transform, CryptoStreamMode.Write))
            {
                cs.Write(buffer, 0, buffer.Length);
            }
            return stream.ToArray();
        }

        /// <summary>
        /// Calculates the valid key size options.
        /// </summary>
        /// <returns></returns>
        public IList<int> CalculateKeySizeOptions()
        {
            MinKeySize = _rijndaelManaged.LegalKeySizes[0].MinSize;
            MaxKeySize = _rijndaelManaged.LegalKeySizes[0].MaxSize;
            KeyStepSize = _rijndaelManaged.LegalKeySizes[0].SkipSize;
            var size = MinKeySize;
            var kso = new List<int>();
            while (size <= MaxKeySize)
            {
                kso.Add(size);
                size = size + KeyStepSize;
            }

            return kso;
        }
    }
}