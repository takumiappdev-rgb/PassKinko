using System;
using System.Security.Cryptography;

namespace PassKinko.App.Security;

public sealed class CryptoKeys : IDisposable
{
    public byte[] EncryptionKey { get; }
    public byte[] MacKey { get; }
    private bool _disposed;

    public CryptoKeys(byte[] encryptionKey, byte[] macKey)
    {
        EncryptionKey = encryptionKey;
        MacKey = macKey;
    }

    public void Dispose()
    {
        if (_disposed) return;
        CryptographicOperations.ZeroMemory(EncryptionKey);
        CryptographicOperations.ZeroMemory(MacKey);
        _disposed = true;
    }
}
