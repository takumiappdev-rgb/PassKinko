using System;
using System.Security.Cryptography;
using System.Text;

namespace PassKinko.App.Security;

public sealed class VaultCryptoService
{
    private const string Prefix = "v10:";
    private const int NonceSize = 12;
    private const int TagSize = 16;

    public string EncryptString(string plainText, CryptoKeys keys)
    {
        if (string.IsNullOrEmpty(plainText)) return string.Empty;

        var nonce = RandomNumberGenerator.GetBytes(NonceSize);
        var plain = Encoding.UTF8.GetBytes(plainText);
        var cipher = new byte[plain.Length];
        var tag = new byte[TagSize];

        using (var aes = new AesGcm(keys.EncryptionKey, TagSize))
        {
            aes.Encrypt(nonce, plain, cipher, tag);
        }

        CryptographicOperations.ZeroMemory(plain);

        var packed = new byte[NonceSize + TagSize + cipher.Length];
        Buffer.BlockCopy(nonce, 0, packed, 0, NonceSize);
        Buffer.BlockCopy(tag, 0, packed, NonceSize, TagSize);
        Buffer.BlockCopy(cipher, 0, packed, NonceSize + TagSize, cipher.Length);
        return Prefix + Convert.ToBase64String(packed);
    }

    public string DecryptString(string encryptedText, CryptoKeys keys)
    {
        if (string.IsNullOrEmpty(encryptedText)) return string.Empty;
        if (!encryptedText.StartsWith(Prefix, StringComparison.Ordinal))
        {
            throw new CryptographicException("未対応の暗号化形式です。v10形式のデータではありません。");
        }

        var packed = Convert.FromBase64String(encryptedText.Substring(Prefix.Length));
        if (packed.Length < NonceSize + TagSize)
        {
            throw new CryptographicException("暗号化データが破損しています。");
        }

        var cipherLength = packed.Length - NonceSize - TagSize;
        var nonce = new byte[NonceSize];
        var tag = new byte[TagSize];
        var cipher = new byte[cipherLength];
        Buffer.BlockCopy(packed, 0, nonce, 0, NonceSize);
        Buffer.BlockCopy(packed, NonceSize, tag, 0, TagSize);
        Buffer.BlockCopy(packed, NonceSize + TagSize, cipher, 0, cipherLength);

        var plain = new byte[cipherLength];
        try
        {
            using (var aes = new AesGcm(keys.EncryptionKey, TagSize))
            {
                aes.Decrypt(nonce, cipher, tag, plain);
            }
            return Encoding.UTF8.GetString(plain);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plain);
        }
    }
}
