using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace AesCryptographyExample
{
    public static class Encryption
    {
        //references:
        // https://docs.microsoft.com/pt-br/dotnet/api/system.security.cryptography.aes?view=net-5.0
        // https://docs.microsoft.com/pt-br/dotnet/standard/security/encrypting-data
        
        public static string Encrypt(string text, string password)
        {
            var key = GetHash(password);
            
            using var aes = Aes.Create();
            var iv = aes.IV;

            var encrypted = EncryptStringToBytes_Aes(text, key, aes.IV);
            
            var result = new byte[iv.Length + encrypted.Length];
            Array.Copy(iv, 0, result, 0, iv.Length);
            Array.Copy(encrypted, 0, result, iv.Length, encrypted.Length);

            var encryptedResult = $"{System.Convert.ToBase64String(result)}";
            return encryptedResult;
        }

        public static string Decrypt(string text, string password)
        {
            var key = GetHash(password);
            
            using var aes = Aes.Create();
            var encrypted = Convert.FromBase64String(text);
            
            var iv = new byte[aes.IV.Length];
            Array.Copy(encrypted, iv, iv.Length);
            
            var cipherText = new byte[encrypted.Length - iv.Length];
            Array.Copy(encrypted, iv.Length, cipherText, 0, cipherText.Length);
            
            string decrypted = DecryptStringFromBytes_Aes(cipherText, key, iv);
            return decrypted;
        }

        private static byte[] EncryptStringToBytes_Aes(string plainText, byte[] Key, byte[] IV)
        {
            if (plainText == null || plainText.Length <= 0)
                throw new ArgumentNullException(nameof(plainText));
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException(nameof(Key));
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException(nameof(IV));
            byte[] encrypted;

            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                var encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                using var msEncrypt = new MemoryStream();
                using var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write);
                using (var swEncrypt = new StreamWriter(csEncrypt))
                swEncrypt.Write(plainText);
                encrypted = msEncrypt.ToArray();
            }

            return encrypted;
        }

        private static string DecryptStringFromBytes_Aes(byte[] cipherText, byte[] Key, byte[] IV)
        {
            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException(nameof(cipherText));
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException(nameof(Key));
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException(nameof(IV));

            string plaintext = null;
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                var decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                using var msDecrypt = new MemoryStream(cipherText);
                using var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read);
                using var srDecrypt = new StreamReader(csDecrypt);
                plaintext = srDecrypt.ReadToEnd();
            }

            return plaintext;
        }

        public static byte[] GetHash(string text)
        {
            var bytes = Encoding.UTF8.GetBytes(text);
            using var hashstring = new SHA256Managed();
            var hash = hashstring.ComputeHash(bytes);
            return hash;
        }
    }
}
