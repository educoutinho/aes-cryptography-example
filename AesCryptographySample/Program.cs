using System;
using System.Text;

namespace AesCryptographySample
{
    public class Program
    {
        public static void Main()
        {
            string text = "Manga é melhor doque maça";
            string password = "79216CEA-3725-4A61-93C9-9C6715E8341E";
            
            for (int i = 0; i < 5; i++)
            {
                var encrypted = Encryption.Encrypt(text, password);
                var decrypted = Encryption.Decrypt(encrypted, password);

                Console.WriteLine($"Text: {text}");
                Console.WriteLine($"Encrypter: {encrypted}");
                Console.WriteLine($"Decrypted: {decrypted}");
                Console.WriteLine();
            }
                        
            Console.ReadKey();
        }
    }
}
