namespace TalesFromTheCrypto.ViewModels
{
    using System;
    using System.Collections.Generic;
    using System.ComponentModel;
    using System.Linq;
    using System.Runtime.CompilerServices;
    using System.Security.Cryptography;
    using System.Windows;
    using Annotations;
    using Crypto;
    using Inf;

    /// <summary>
    /// The Main Window View Model
    /// </summary>
    /// <seealso cref="System.ComponentModel.INotifyPropertyChanged" />
    public class MainWindowViewModel : INotifyPropertyChanged
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="MainWindowViewModel"/> class.
        /// </summary>
        public MainWindowViewModel()
        {
            CryptoGenerators = new List<ICryptoGenerator> {new AesCrypto()};
            OnPropertyChanged(nameof(CryptoGenerators));
        }

        #region Test Value Properties

        private string _originalString;

        /// <summary>
        /// Gets or sets the original unencrpted string.
        /// </summary>
        /// <value>
        /// The original string.
        /// </value>
        public string OriginalString
        {
            get { return _originalString; }
            set
            {
                _originalString = value;
                EncryptStringCommand.RaiseCanExecuteChanged();
            }
        }

        /// <summary>
        /// Gets or sets the encrypted string.
        /// </summary>
        /// <value>
        /// The encrypted string.
        /// </value>
        public string EncryptedString { get; set; }

        /// <summary>
        /// Gets or sets the decrypted string.
        /// </summary>
        /// <value>
        /// The decrypted string.
        /// </value>
        public string DecryptedString { get; set; }

        #endregion

        #region Key Data

        /// <summary>
        /// Gets the current cryptographic key from the selected cryptographic class.
        /// </summary>
        /// <value>
        /// The key.
        /// </value>
        public string Key => SelectedCryptoClass?.Key.PrintBytes();

        /// <summary>
        /// Gets the current cryptographic vector from the selected cryptographic class.
        /// </summary>
        /// <value>
        /// The vector.
        /// </value>
        public string Vector => SelectedCryptoClass?.InitialisationVector.PrintBytes();

        #endregion

        #region Commands

        private CommandHandler _intitialiseCommand;

        /// <summary>
        /// Gets the intitialise command.
        /// </summary>
        /// <value>
        /// The intitialise command.
        /// </value>
        public CommandHandler IntitialiseCommand
        {
            get { return _intitialiseCommand ?? (_intitialiseCommand = new CommandHandler(InitialiseCommandExecuted, CanInitaliseCryto)); }
        }

        private CommandHandler _encryptStringCommand;

        /// <summary>
        /// Gets the encrypt string command.
        /// </summary>
        /// <value>
        /// The encrypt string command.
        /// </value>
        public CommandHandler EncryptStringCommand
        {
            get { return _encryptStringCommand ?? (_encryptStringCommand = new CommandHandler(EncryptStringCommandExecuted, CanEncryptOriginalString)); }
        }

        private CommandHandler _decryptStringCommand;

        /// <summary>
        /// Gets the decrypt string command.
        /// </summary>
        /// <value>
        /// The decrypt string command.
        /// </value>
        public CommandHandler DecryptStringCommand
        {
            get { return _decryptStringCommand ?? (_decryptStringCommand = new CommandHandler(DecryptStringCommandExecuted, CanDecryptEncryptedString)); }
        }

        /// <summary>
        /// Determines whether this instance [can decrypt encrypted string] the specified parameter.
        /// </summary>
        /// <param name="param">The parameter.</param>
        /// <returns>
        ///   <c>true</c> if this instance [can decrypt encrypted string] the specified parameter; otherwise, <c>false</c>.
        /// </returns>
        private bool CanDecryptEncryptedString(object param)
        {
            return SelectedCryptoClass != null && EncryptedString != null;
        }

        /// <summary>
        /// Determines whether this instance [can encrypt original string] the specified parameter.
        /// </summary>
        /// <param name="param">The parameter.</param>
        /// <returns>
        ///   <c>true</c> if this instance [can encrypt original string] the specified parameter; otherwise, <c>false</c>.
        /// </returns>
        private bool CanEncryptOriginalString(object param)
        {
            return CanInitaliseCryto(param) && OriginalString != null;
        }

        /// <summary>
        /// Encrypts the string command executed.
        /// </summary>
        /// <param name="param">The parameter.</param>
        private void EncryptStringCommandExecuted(object param)
        {
            try
            {
                EncryptedString = SelectedCryptoClass.Encrypt(OriginalString);
                OnPropertyChanged(nameof(EncryptedString));
                DecryptStringCommand.RaiseCanExecuteChanged();
            }
            catch (CryptographicException ex)
            {
                MessageBox.Show(Application.Current.MainWindow, ex.Message, "Cryptographic Error");
            }
        }

        /// <summary>
        /// Decrypts the string command executed.
        /// </summary>
        /// <param name="param">The parameter.</param>
        private void DecryptStringCommandExecuted(object param)
        {
            DecryptedString = SelectedCryptoClass.Decrypt(EncryptedString);
            OnPropertyChanged(nameof(DecryptedString));
        }

        /// <summary>
        /// Determines whether this instance [can initalise cryto] the specified parameter.
        /// </summary>
        /// <param name="param">The parameter.</param>
        /// <returns>
        ///   <c>true</c> if this instance [can initalise cryto] the specified parameter; otherwise, <c>false</c>.
        /// </returns>
        private bool CanInitaliseCryto(object param)
        {
            return SelectedCryptoClass != null;
        }

        /// <summary>
        /// Initialises the command executed.
        /// </summary>
        /// <param name="param">The parameter.</param>
        private void InitialiseCommandExecuted(object param)
        {
            SelectedCryptoClass.Initialise();
            ResetUI();

            OnPropertyChanged(nameof(Key));
            OnPropertyChanged(nameof(Vector));
            OnPropertyChanged(nameof(CipherModes));
            OnPropertyChanged(nameof(PaddingModes));
            OnPropertyChanged(nameof(SelectedCipherMode));
            OnPropertyChanged(nameof(SelectedPaddingMode));
        }

        #endregion

        #region Crypto Class Properties

        /// <summary>
        /// Gets the list of available crypto generators.
        /// </summary>
        /// <value>
        /// The crypto generators.
        /// </value>
        public IList<ICryptoGenerator> CryptoGenerators { get; }

        private ICryptoGenerator _selectedCryptoClass;

        /// <summary>
        /// Gets or sets the selected crypto class.
        /// </summary>
        /// <value>
        /// The selected crypto class.
        /// </value>
        public ICryptoGenerator SelectedCryptoClass
        {
            get { return _selectedCryptoClass; }
            set
            {
                _selectedCryptoClass = value;

                OnPropertyChanged(nameof(KeySizes));
                OnPropertyChanged(nameof(CipherModes));
                OnPropertyChanged(nameof(PaddingModes));
                OnPropertyChanged(nameof(CryptoDescription));

                SelectedKeySize = KeySizes.FirstOrDefault(x => _selectedCryptoClass.CurrentKeySize != null && x == _selectedCryptoClass.CurrentKeySize.Value);
                OnPropertyChanged(nameof(SelectedKeySize));

                ResetUI();
            }
        }

        /// <summary>
        /// Gets the valid key sizes for the selected crypto class.
        /// </summary>
        /// <value>
        /// The key sizes.
        /// </value>
        public IList<int> KeySizes => SelectedCryptoClass?.KeySizeOptions;

        private int _selectedKeySize;

        /// <summary>
        /// Gets or sets the size of the key to be used.
        /// </summary>
        /// <value>
        /// The size of the selected key.
        /// </value>
        public int SelectedKeySize
        {
            get { return _selectedKeySize; }
            set
            {
                _selectedKeySize = value;
                _selectedCryptoClass.SetKeySize(value);
            }
        }

        public IList<string> CipherModes
        {
            get { return _selectedCryptoClass?.AvailableModes; }
        }

        public string SelectedCipherMode
        {
            get { return _selectedCryptoClass?.Mode; }
            set
            {
                _selectedCryptoClass.SetCipherMode(value);
            }
        }

        public IList<string> PaddingModes
        {
            get { return _selectedCryptoClass?.AvailablePaddingModes; }
        }

        public string SelectedPaddingMode
        {
            get { return _selectedCryptoClass?.Padding; }
            set
            {
                _selectedCryptoClass.SetPaddingMode(value);
            }
        }

        /// <summary>
        /// Gets the selected crypto class description.
        /// </summary>
        /// <value>
        /// The crypto description.
        /// </value>
        public string CryptoDescription => SelectedCryptoClass?.CryptoDescription;

        #endregion

        #region UI Code

        /// <summary>
        /// Resets the UI.
        /// </summary>
        private void ResetUI()
        {
            OriginalString = null;
            OnPropertyChanged(nameof(OriginalString));

            EncryptedString = null;
            OnPropertyChanged(nameof(EncryptedString));

            DecryptedString = null;
            OnPropertyChanged(nameof(DecryptedString));

            IntitialiseCommand.RaiseCanExecuteChanged();
            EncryptStringCommand.RaiseCanExecuteChanged();
            DecryptStringCommand.RaiseCanExecuteChanged();
        }

        /// <summary>
        /// Occurs when a property value changes.
        /// </summary>
        public event PropertyChangedEventHandler PropertyChanged;

        /// <summary>
        /// Called when [property changed].
        /// </summary>
        /// <param name="propertyName">Name of the property.</param>
        [NotifyPropertyChangedInvocator]
        private void OnPropertyChanged([CallerMemberName] string propertyName = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }

        #endregion

    }
}