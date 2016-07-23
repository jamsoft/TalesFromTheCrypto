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
    public class AesRijndaelCrypto : ICryptoGenerator
    {
        private ICryptoTransform _encryptor, _decryptor;
        private UTF8Encoding _encoder;
        private readonly RijndaelManaged _rijndaelManaged;

        /// <summary>
        /// Initializes a new instance of the <see cref="AesRijndaelCrypto"/> class.
        /// </summary>
        public AesRijndaelCrypto()
        {
            _rijndaelManaged = new RijndaelManaged();

            CryptoName = "AES (RijndaelManaged)";
            CryptoDescription = "The Advanced Encryption Standard (AES), also known as Rijndael (its original name), is a specification for the encryption of electronic data established by the U.S. National Institute of Standards and Technology (NIST) in 2001.";
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
        /// Gets the size of the currently selected keysize.
        /// </summary>
        /// <value>
        /// The size of the current key.
        /// </value>
        public int? CurrentKeySize
        {
            get { return _rijndaelManaged?.KeySize; }
        }

        /// <summary>
        /// Gets the minimum size of the legal crypto key size.
        /// </summary>
        public int MinBlockSize { get; private set; }

        /// <summary>
        /// Gets the maximum size of the legal crypto key size.
        /// </summary>
        public int MaxBlockSize { get; private set; }

        /// <summary>
        /// Gets the size of the legal key interval step size between the minimum and maximum key sizes.
        /// </summary>
        public int BlockStepSize { get; private set; }

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
        public int? CurrentBlockSize { get { return _rijndaelManaged?.BlockSize; } }

        /// <summary>
        /// Gets the current cipher mode.
        /// </summary>
        /// <value>
        /// The current cipher mode.
        /// </value>
        public string CurrentCipherMode
        {
            get { return Enum.GetName(typeof(CipherMode), _rijndaelManaged.Mode); }
        }

        /// <summary>
        /// Gets the current padding mode.
        /// </summary>
        /// <value>
        /// The current padding mode.
        /// </value>
        public string CurrentPaddingMode { get { return Enum.GetName(typeof(PaddingMode), _rijndaelManaged.Padding); } }

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
        /// Gets or sets the encryption key.
        /// </summary>
        public byte[] Key { get; set; }

        /// <summary>
        /// Gets the current crypto mode.
        /// </summary>
        /// <value>
        /// The mode.
        /// </value>
        public string Mode => _rijndaelManaged.Mode.ToString();

        /// <summary>
        /// Gets the padding mode.
        /// </summary>
        /// <value>
        /// The padding.
        /// </value>
        public string Padding => _rijndaelManaged.Padding.ToString();

        /// <summary>
        /// Gets or sets the initialisation vector.
        /// </summary>
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
        /// Calculates the block size options.
        /// </summary>
        /// <returns></returns>
        public IList<int> CalculateBlockSizeOptions()
        {
            MinBlockSize = _rijndaelManaged.LegalBlockSizes[0].MinSize;
            MaxBlockSize = _rijndaelManaged.LegalBlockSizes[0].MaxSize;
            BlockStepSize = _rijndaelManaged.LegalBlockSizes[0].SkipSize;
            var size = MinBlockSize;
            var bso = new List<int>();
            while (size <= MaxBlockSize)
            {
                bso.Add(size);
                size = size + BlockStepSize;
            }

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
                var opt = new List<string>(Enum.GetNames(_rijndaelManaged.Mode.GetType()));

                // RijndaelManaged does not support these modes
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
        /// Sets the blocksize.
        /// </summary>
        /// <param name="blockSize">Size of the block.</param>
        public void SetBlockSize(int blockSize)
        {
            _rijndaelManaged.BlockSize = blockSize;
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
            // we create the encryptor each time in order to respect any UI setting changes
            _encryptor = _rijndaelManaged.CreateEncryptor(Key, InitialisationVector);
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
            // we create the decryptor each time in order to respect any UI setting changes
            _decryptor = _rijndaelManaged.CreateDecryptor(Key, InitialisationVector);
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