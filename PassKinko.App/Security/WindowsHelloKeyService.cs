using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using PassKinko.App.Models;

namespace PassKinko.App.Security;

public sealed class WindowsHelloKeyService
{
    private static readonly byte[] Entropy = Encoding.UTF8.GetBytes("PassKinko.V002.WindowsHelloKeys");
    private const int CryptProtectUiForbidden = 0x1;

    public bool HasProtectedKeys(AppSettings settings)
    {
        return settings.UseWindowsHello && !string.IsNullOrWhiteSpace(settings.WindowsHelloKeyProtectedBase64);
    }

    public void ProtectInto(AppSettings settings, CryptoKeys keys)
    {
        var payload = new ProtectedKeys
        {
            Version = 1,
            CreatedAtUtc = DateTime.UtcNow,
            EncryptionKeyBase64 = Convert.ToBase64String(keys.EncryptionKey),
            MacKeyBase64 = Convert.ToBase64String(keys.MacKey)
        };
        var json = JsonSerializer.Serialize(payload);
        var plain = Encoding.UTF8.GetBytes(json);
        try
        {
            settings.WindowsHelloKeyProtectedBase64 = Convert.ToBase64String(Protect(plain));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plain);
        }
    }

    public CryptoKeys Unprotect(AppSettings settings)
    {
        if (!HasProtectedKeys(settings))
        {
            throw new InvalidDataException("Windows Hello解除用の保護鍵が登録されていません。");
        }

        var protectedBytes = Convert.FromBase64String(settings.WindowsHelloKeyProtectedBase64);
        var plain = UnprotectBytes(protectedBytes);
        try
        {
            var payload = JsonSerializer.Deserialize<ProtectedKeys>(Encoding.UTF8.GetString(plain))
                ?? throw new InvalidDataException("Windows Hello解除用の保護鍵を読み込めません。");
            if (payload.Version != 1)
            {
                throw new InvalidDataException("未対応のWindows Hello保護鍵形式です。");
            }

            var encryptionKey = Convert.FromBase64String(payload.EncryptionKeyBase64);
            var macKey = Convert.FromBase64String(payload.MacKeyBase64);
            if (encryptionKey.Length != 32 || macKey.Length != 32)
            {
                throw new InvalidDataException("Windows Hello解除用の保護鍵が破損しています。");
            }
            return new CryptoKeys(encryptionKey, macKey);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plain);
        }
    }

    public void Clear(AppSettings settings)
    {
        settings.UseWindowsHello = false;
        settings.WindowsHelloKeyProtectedBase64 = string.Empty;
    }

    private static byte[] Protect(byte[] plain)
    {
        var dataIn = CreateBlob(plain);
        var entropy = CreateBlob(Entropy);
        DATA_BLOB dataOut = default;
        try
        {
            if (!CryptProtectData(ref dataIn, "PassKinko Windows Hello Keys", ref entropy, IntPtr.Zero, IntPtr.Zero, CryptProtectUiForbidden, out dataOut))
            {
                throw new InvalidOperationException("DPAPIによるWindows Hello解除鍵の保護に失敗しました。Win32Error=" + Marshal.GetLastWin32Error());
            }
            return ReadBlob(dataOut);
        }
        finally
        {
            FreeInputBlob(dataIn);
            FreeInputBlob(entropy);
            FreeOutputBlob(dataOut);
        }
    }

    private static byte[] UnprotectBytes(byte[] protectedBytes)
    {
        var dataIn = CreateBlob(protectedBytes);
        var entropy = CreateBlob(Entropy);
        DATA_BLOB dataOut = default;
        IntPtr description = IntPtr.Zero;
        try
        {
            if (!CryptUnprotectData(ref dataIn, out description, ref entropy, IntPtr.Zero, IntPtr.Zero, CryptProtectUiForbidden, out dataOut))
            {
                throw new InvalidDataException("DPAPIによるWindows Hello解除鍵の復元に失敗しました。Win32Error=" + Marshal.GetLastWin32Error());
            }
            return ReadBlob(dataOut);
        }
        finally
        {
            FreeInputBlob(dataIn);
            FreeInputBlob(entropy);
            if (description != IntPtr.Zero) LocalFree(description);
            FreeOutputBlob(dataOut);
        }
    }

    private static DATA_BLOB CreateBlob(byte[] bytes)
    {
        var blob = new DATA_BLOB { cbData = bytes.Length, pbData = Marshal.AllocHGlobal(bytes.Length) };
        Marshal.Copy(bytes, 0, blob.pbData, bytes.Length);
        return blob;
    }

    private static byte[] ReadBlob(DATA_BLOB blob)
    {
        if (blob.pbData == IntPtr.Zero || blob.cbData <= 0) return Array.Empty<byte>();
        var bytes = new byte[blob.cbData];
        Marshal.Copy(blob.pbData, bytes, 0, blob.cbData);
        return bytes;
    }

    private static void FreeInputBlob(DATA_BLOB blob)
    {
        if (blob.pbData != IntPtr.Zero) Marshal.FreeHGlobal(blob.pbData);
    }

    private static void FreeOutputBlob(DATA_BLOB blob)
    {
        if (blob.pbData != IntPtr.Zero) LocalFree(blob.pbData);
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct DATA_BLOB
    {
        public int cbData;
        public IntPtr pbData;
    }

    private sealed class ProtectedKeys
    {
        public int Version { get; set; }
        public DateTime CreatedAtUtc { get; set; }
        public string EncryptionKeyBase64 { get; set; } = string.Empty;
        public string MacKeyBase64 { get; set; } = string.Empty;
    }

    [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CryptProtectData(
        ref DATA_BLOB pDataIn,
        string? szDataDescr,
        ref DATA_BLOB pOptionalEntropy,
        IntPtr pvReserved,
        IntPtr pPromptStruct,
        int dwFlags,
        out DATA_BLOB pDataOut);

    [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CryptUnprotectData(
        ref DATA_BLOB pDataIn,
        out IntPtr ppszDataDescr,
        ref DATA_BLOB pOptionalEntropy,
        IntPtr pvReserved,
        IntPtr pPromptStruct,
        int dwFlags,
        out DATA_BLOB pDataOut);

    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr hMem);
}
