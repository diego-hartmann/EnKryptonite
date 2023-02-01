using System;
using System.Text;
using System.Security.Cryptography;
using System.IO;

namespace EnKryptonite
{
    // Reference from EVERTON JOSÉ BENEDICTO's article: http://www.linhadecodigo.com.br/artigo/3078/criptografando-dados-com-csharp.aspx
    public class Encryptor {

      
        #region =================== PRIVATE FILEDS ====================
        private SymmetricAlgorithm algorithm;
        private EncryptorProvider encryptorProvider;
        private string key = string.Empty;
        #endregion ====================================================


        #region =================== PRIVATE METHODS ===================
        /// <summary>Constructor helper to modulate the logic.</summary>
        /// <param name="secretKey">The key received from constructor.</param>
        /// <param name="_cryptProvider">The provider received from constructor</param>
        private void EncryptorConstructor(string secretKey, EncryptorProvider _cryptProvider)
        {
            this.key = secretKey;
            this.encryptorProvider = _cryptProvider;
            this.algorithm.Mode = CipherMode.CBC;
            switch (this.encryptorProvider)
            {
                case EncryptorProvider.Rijndael:
                    this.algorithm = new RijndaelManaged();
                    break;
                case EncryptorProvider.RC2:
                    this.algorithm = new RC2CryptoServiceProvider();
                    break;
                case EncryptorProvider.DES:
                    this.algorithm = new DESCryptoServiceProvider();
                    break;
                case EncryptorProvider.TripleDES:
                    this.algorithm = new TripleDESCryptoServiceProvider();
                    break;
            }
        }

        /// <summary>Symetric algorithm vector initalizator.</summary>
        private void SetInitVector() {
            switch (this.encryptorProvider) {
                case EncryptorProvider.Rijndael:
                    this.algorithm.IV = new byte[] { 0xf, 0x6f, 0x13, 0x2e, 0x35, 0xc2, 0xcd, 0xf9, 0x5, 0x46, 0x9c, 0xea, 0xa8, 0x4b, 0x73, 0xcc };
                    break;
                default:
                    this.algorithm.IV = new byte[] { 0xf, 0x6f, 0x13, 0x2e, 0x35, 0xc2, 0xcd, 0xf9 };
                    break;
            }
        }

        /// <summary>Generates the key to a valid cryptograpfy inside the array.</summary>
        /// <returns>Key with bites array.</returns>
        private byte[] GetSanatizedKey() {
            // Ajusts key length if needed, and returns a valid key.
            if (this.algorithm.LegalKeySizes.Length > 0) {
                // Keys lenght (bits)
                int keySize = this.key.Length * 8;
                int minSize = this.algorithm.LegalKeySizes[0].MinSize;
                int maxSize = this.algorithm.LegalKeySizes[0].MaxSize;
                int skipSize = this.algorithm.LegalKeySizes[0].SkipSize;

                // Searches for maximum key value.
                if (keySize > maxSize) this.key = this.key.Substring(0, maxSize / 8);

                // Sets a valid size
                else if (keySize < maxSize) {
                    int validSize = (keySize <= minSize) ? minSize : (keySize - keySize % skipSize) + skipSize;
                    // Fills the key with asteristic so it corrects the size
                    if (keySize < validSize) this.key = this.key.PadRight(validSize / 8, '*');
                }
            }

            PasswordDeriveBytes _key = new PasswordDeriveBytes(this.key, ASCIIEncoding.ASCII.GetBytes(string.Empty));
            return _key.GetBytes(this.key.Length);
        }
        #endregion ====================================================


        #region =================== CONSTRUCTORS ========================
        /// <summary>Default constructor with standard cryptography type (Rijndael).</summary>
        /// <param name="secretKey">Secret key.</param>
        public Encryptor(string secretKey) => EncryptorConstructor(secretKey, EncryptorProvider.Rijndael);
        

        /// <summary>Constructor with provided cryptography type.</summary>
        /// <param name="secretKey">Secret key.</param>
        /// <param name="cryptProvider">Cryptography type.</param>
        public Encryptor(string secretKey, EncryptorProvider _cryptProvider) => EncryptorConstructor(secretKey, _cryptProvider);
        
        #endregion ================================================================


        #region  ================== PUBLIC METHODS ================================


        /// <summary>Encrypts the data.</summary>
        /// <param name="plainText">Text to be encrypted.</param>
        /// <returns>Encrypted text.</returns>
        public string Encrypt(string text) {
            
            byte[] plainByte = Encoding.UTF8.GetBytes(text);
            byte[] keyByte = GetSanatizedKey();
            
            this.algorithm.Key = keyByte;
            SetInitVector();

            // Crypt interface / Creates crypt object
            ICryptoTransform cryptoTransform = this.algorithm.CreateEncryptor();

            // Records the encrypted data into MemoryStream
            MemoryStream _memoryStream = new MemoryStream();
            CryptoStream _cryptoStream = new CryptoStream(_memoryStream, cryptoTransform, CryptoStreamMode.Write);
            _cryptoStream.Write(plainByte, 0, plainByte.Length);
            _cryptoStream.FlushFinalBlock();

            // Seaches for encrypted bytes length
            byte[] cryptoByte = _memoryStream.ToArray();

            // Converts to 64 base string for latter usage in a xml
            return Convert.ToBase64String(cryptoByte, 0, cryptoByte.GetLength(0));
        }


        /// <summary>Decrypts the data.</summary>
        /// <param name="text">Text to be decrypted.</param>
        /// <returns>Decrypted text.</returns>
        public string Decrypt(string text) {
            
            // Converts the 64 base string into a bytes array
            byte[] cryptoByte = Convert.FromBase64String(text);
            byte[] keyByte = GetSanatizedKey();

            this.algorithm.Key = keyByte;
            SetInitVector();

            // Crypt interface / Creates crypt object
            ICryptoTransform cryptoTransform = this.algorithm.CreateDecryptor();

            try {

                MemoryStream _memoryStream = new MemoryStream(cryptoByte, 0, cryptoByte.Length);
                CryptoStream _cryptoStream = new CryptoStream(_memoryStream, cryptoTransform, CryptoStreamMode.Read);
                
                // Searches for CryptoStream result
                StreamReader _streamReader = new StreamReader(_cryptoStream);
                return _streamReader.ReadToEnd();

            } catch {
                return null;
            }
        }
        #endregion =====================================================================================
    }

}

