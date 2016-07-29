namespace TalesFromTheCrypto.Crypto
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Security.Cryptography;
    using System.Text;
    using Inf;

    public class AesCrypto : ICryptoGenerator
    {
        private ICryptoTransform _encryptor, _decryptor;
        private UTF8Encoding _encoder;
        private AesManaged _aesManaged;

        public AesCrypto()
        {
            _aesManaged = new AesManaged();

            CryptoName = "AES (AesManaged)";
            CryptoDescription = "The Advanced Encryption Standard (AES), also known as Rijndael (its original name pronounced rain-dahl), is a specification for the encryption of electronic data established by the U.S. National Institute of Standards and Technology (NIST) in 2001." + Environment.NewLine +
            "AES is a subset of the Rijndael cipher developed by two Belgian cryptographers, Joan Daemen and Vincent Rijmen, who submitted a proposal to NIST during the AES selection process. Rijndael is a family of ciphers with different key and block sizes." + Environment.NewLine +
            "AES has been adopted by the U.S. government and is now used worldwide. It supersedes the Data Encryption Standard (DES), which was published in 1977. The algorithm described by AES is a symmetric-key algorithm, meaning the same key is used for both encrypting and decrypting the data.";
        }

        /// <summary>
        /// Gets a value indicating whether this instance is initialised.
        /// </summary>
        /// <value>
        /// <c>true</c> if this instance is initialised; otherwise, <c>false</c>.
        /// </value>
        public bool IsInitialised { get; private set; }

        /// <summary>
        /// Gets the name of the crypto type supported.
        /// </summary>
        public string CryptoName { get; }

        /// <summary>
        /// Gets the text describing the crypto algorithm.
        /// </summary>
        public string CryptoDescription { get; }

        /// <summary>
        /// Gets the crypto type description.
        /// </summary>
        /// <value>
        /// The crypto type description.
        /// </value>
        public string CryptoTypeDescription { get { return CryptoType.SymmetricAlgorithm; } }

        /// <summary>
        /// Gets or sets the encryption key.
        /// </summary>
        public byte[] Key { get; set; }

        /// <summary>
        /// Gets the current crypto mode.
        /// </summary>
        /// <value>
        /// The mode.
        /// </value>
        public string Mode => _aesManaged.Mode.ToString();

        /// <summary>
        /// Gets the padding mode.
        /// </summary>
        /// <value>
        /// The padding.
        /// </value>
        public string Padding => _aesManaged.Padding.ToString();

        /// <summary>
        /// Gets or sets the initialisation vector.
        /// </summary>
        public byte[] InitialisationVector { get; set; }

        /// <summary>
        /// Gets the minimum size of the legal crypto key size.
        /// </summary>
        public int MinKeySize { get; set; }

        /// <summary>
        /// Gets the maximum size of the legal crypto key size.
        /// </summary>
        public int MaxKeySize { get; set; }

        /// <summary>
        /// Gets the size of the legal key interval step size between the minimum and maximum key sizes.
        /// </summary>
        public int KeyStepSize { get; set; }

        /// <summary>
        /// Gets the valid key size options for the crytography method.
        /// </summary>
        public IList<int> KeySizeOptions { get { return CalculateKeySizeOptions(); } }

        /// <summary>
        /// Gets the size of the currently selected keysize.
        /// </summary>
        /// <value>
        /// The size of the current key.
        /// </value>
        public int? CurrentKeySize { get { return _aesManaged?.KeySize; } }

        /// <summary>
        /// Gets the minimum size of the legal crypto key size.
        /// </summary>
        public int MinBlockSize { get; set; }

        /// <summary>
        /// Gets the maximum size of the legal crypto key size.
        /// </summary>
        public int MaxBlockSize { get; set; }

        /// <summary>
        /// Gets the size of the legal key interval step size between the minimum and maximum key sizes.
        /// </summary>
        public int BlockStepSize { get; set; }

        /// <summary>
        /// Gets the block size options.
        /// </summary>
        /// <value>
        /// The block size options.
        /// </value>
        public IList<int> BlockSizeOptions { get { return CalculateBlockSizeOptions(); } }

        /// <summary>
        /// Gets the size of the current block.
        /// </summary>
        /// <value>
        /// The size of the current block.
        /// </value>
        public int? CurrentBlockSize { get { return _aesManaged?.BlockSize; } }

        /// <summary>
        /// Gets the current cipher mode.
        /// </summary>
        /// <value>
        /// The current cipher mode.
        /// </value>
        public string CurrentCipherMode { get { return Enum.GetName(typeof(CipherMode), _aesManaged.Mode); } }

        /// <summary>
        /// Gets the current cipher mode.
        /// </summary>
        /// <value>
        /// The current cipher mode.
        /// </value>
        public string CurrentCipherModeget { get { return Enum.GetName(typeof(CipherMode), _aesManaged.Mode); } }

        /// <summary>
        /// Gets the current padding mode.
        /// </summary>
        /// <value>
        /// The current padding mode.
        /// </value>
        public string CurrentPaddingMode { get { return Enum.GetName(typeof(PaddingMode), _aesManaged.Padding); } }

        /// <summary>
        /// Initialises the crypto class instance.
        /// </summary>
        public void Initialise()
        {
            GenerateKey();
            GenerateVector();
            _encoder = new UTF8Encoding();
            IsInitialised = true;
        }

        /// <summary>
        /// Calculates the valid key size options.
        /// </summary>
        /// <returns></returns>
        public IList<int> CalculateKeySizeOptions()
        {
            MinKeySize = _aesManaged.LegalKeySizes[0].MinSize;
            MaxKeySize = _aesManaged.LegalKeySizes[0].MaxSize;
            KeyStepSize = _aesManaged.LegalKeySizes[0].SkipSize;
            var size = MinKeySize;
            var kso = new List<int>();
            while (size <= MaxKeySize)
            {
                kso.Add(size);
                size = size + KeyStepSize;
            }

            return kso;
        }

        /// <summary>
        /// Calculates the block size options.
        /// </summary>
        /// <returns></returns>
        public IList<int> CalculateBlockSizeOptions()
        {
            MinBlockSize = _aesManaged.LegalBlockSizes[0].MinSize;
            MaxBlockSize = _aesManaged.LegalBlockSizes[0].MaxSize;
            BlockStepSize = _aesManaged.LegalBlockSizes[0].SkipSize;

            var bso = new List<int> { 128 };
            return bso;
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
                var opt = new List<string>(Enum.GetNames(_aesManaged.Mode.GetType()));

                // RijndaelManaged does not support these modes
                opt.Remove("CTS");
                opt.Remove("OFB");
                return opt;
            }
        }

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
                var opt = new List<string>(Enum.GetNames(_aesManaged.Padding.GetType()));
                return opt;
            }
        }

        /// <summary>
        /// Sets the size of the key.
        /// </summary>
        /// <param name="keySize">Size of the key.</param>
        public void SetKeySize(int keySize)
        {
            _aesManaged.KeySize = keySize;
        }

        /// <summary>
        /// Sets the blocksize.
        /// </summary>
        /// <param name="blockSize">Size of the block.</param>
        public void SetBlockSize(int blockSize)
        {
            _aesManaged.BlockSize = blockSize;
        }

        /// <summary>
        /// Sets the cipher mode.
        /// </summary>
        /// <param name="mode">The mode.</param>
        public void SetCipherMode(string mode)
        {
            _aesManaged.Mode = (CipherMode)Enum.Parse(typeof(CipherMode), mode);
        }

        /// <summary>
        /// Sets the padding mode.
        /// </summary>
        /// <param name="mode">The mode.</param>
        public void SetPaddingMode(string mode)
        {
            _aesManaged.Padding = (PaddingMode)Enum.Parse(typeof(PaddingMode), mode);
        }

        /// <summary>
        /// Generates the key byte array.
        /// </summary>
        /// <returns>a new byte[]</returns>
        public byte[] GenerateKey()
        {
            _aesManaged.GenerateKey();
            Key = _aesManaged.Key;
            return Key;
        }

        /// <summary>
        /// Generates the vector byte array.
        /// </summary>
        /// <returns>a new byte[]</returns>
        public byte[] GenerateVector()
        {
            _aesManaged.GenerateIV();
            InitialisationVector = _aesManaged.IV;
            return InitialisationVector;
        }

        /// <summary>
        /// Encrypts the specified string value.
        /// </summary>
        /// <param name="value">The original string value.</param>
        /// <returns>the string value in encrypted form</returns>
        public string Encrypt(string value)
        {
            return Convert.ToBase64String(Encrypt(_encoder.GetBytes(value)));
        }

        /// <summary>
        /// Encrypts the specified byte array buffer.
        /// </summary>
        /// <param name="buffer">The original byte[] buffer.</param>
        /// <returns>the byte array buffer in encrypted form</returns>
        public byte[] Encrypt(byte[] buffer)
        {
            // we create the encryptor each time in order to respect any UI setting changes
            _encryptor = _aesManaged.CreateEncryptor(Key, InitialisationVector);
            return Transform(buffer, _encryptor);
        }

        /// <summary>
        /// Decrypts the specified string value.
        /// </summary>
        /// <param name="value">The string value.</param>
        /// <returns>the string value in unencrypted form</returns>
        public string Decrypt(string value)
        {
            return _encoder.GetString(Decrypt(Convert.FromBase64String(value)));
        }

        /// <summary>
        /// Decrypts the specified byte array buffer.
        /// </summary>
        /// <param name="buffer">The buffer.</param>
        /// <returns>the byte array byte[] buffer in unencrypted form</returns>
        public byte[] Decrypt(byte[] buffer)
        {
            // we create the decryptor each time in order to respect any UI setting changes
            _decryptor = _aesManaged.CreateDecryptor(Key, InitialisationVector);
            return Transform(buffer, _decryptor);
        }

        /// <summary>
        /// Transforms the specified buffer.
        /// </summary>
        /// <param name="buffer">The buffer.</param>
        /// <param name="transform">The transform.</param>
        /// <returns></returns>
        private byte[] Transform(byte[] buffer, ICryptoTransform transform)
        {
            using (MemoryStream stream = new MemoryStream())
            {
                using (CryptoStream cs = new CryptoStream(stream, transform, CryptoStreamMode.Write))
                {
                    cs.Write(buffer, 0, buffer.Length);
                }

                return stream.ToArray();
            }
        }
    }
}
