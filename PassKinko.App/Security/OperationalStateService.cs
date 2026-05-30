using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using PassKinko.App.Models;

namespace PassKinko.App.Security;

/// <summary>
/// 失敗回数・一時ロック期限など、マスターパスワード入力前に参照する運用状態をDPAPI(CurrentUser)で保護する。
/// これにより settings.json の平文 FailedUnlockCount / LockoutUntilUtc を直接書き換えても、
/// アプリ起動時には保護済み運用状態が優先される。
/// </summary>
public sealed class OperationalStateService
{
    private static readonly byte[] Entropy = Encoding.UTF8.GetBytes("PassKinko.v10.OperationalState");
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = false };
    private const int CryptProtectUiForbidden = 0x1;

    public void ProtectInto(AppSettings settings)
    {
        if (!settings.IsInitialized) return;

        var state = new OperationalState
        {
            Version = 1,
            FailedUnlockCount = settings.FailedUnlockCount,
            LockoutUntilUtc = settings.LockoutUntilUtc,
            UpdatedAtUtc = DateTime.UtcNow
        };
        var json = JsonSerializer.Serialize(state, JsonOptions);
        var protectedBytes = Protect(Encoding.UTF8.GetBytes(json));
        settings.OperationalStateProtectedBase64 = Convert.ToBase64String(protectedBytes);
    }

    public void LoadInto(AppSettings settings)
    {
        if (!settings.IsInitialized) return;
        if (string.IsNullOrWhiteSpace(settings.OperationalStateProtectedBase64))
        {
            throw new InvalidDataException("運用状態保護データが存在しません。settings.json の欠落、改ざん、または旧形式データの可能性があります。");
        }

        var protectedBytes = Convert.FromBase64String(settings.OperationalStateProtectedBase64);
        var plainBytes = Unprotect(protectedBytes);
        try
        {
            var json = Encoding.UTF8.GetString(plainBytes);
            var state = JsonSerializer.Deserialize<OperationalState>(json)
                ?? throw new InvalidDataException("運用状態保護データを読み込めません。");
            if (state.Version != 1)
            {
                throw new InvalidDataException("未対応の運用状態形式です。");
            }
            if (state.FailedUnlockCount < 0 || state.FailedUnlockCount > 9)
            {
                throw new InvalidDataException("運用状態の失敗回数が不正です。");
            }

            settings.FailedUnlockCount = state.FailedUnlockCount;
            settings.LockoutUntilUtc = state.LockoutUntilUtc;
        }
        finally
        {
            Array.Clear(plainBytes, 0, plainBytes.Length);
        }
    }

    private static byte[] Protect(byte[] plain)
    {
        var dataIn = CreateBlob(plain);
        var entropy = CreateBlob(Entropy);
        DATA_BLOB dataOut = default;
        try
        {
            if (!CryptProtectData(ref dataIn, null, ref entropy, IntPtr.Zero, IntPtr.Zero, CryptProtectUiForbidden, out dataOut))
            {
                throw new InvalidOperationException("DPAPIによる運用状態保護に失敗しました。Win32Error=" + Marshal.GetLastWin32Error());
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

    private static byte[] Unprotect(byte[] protectedBytes)
    {
        var dataIn = CreateBlob(protectedBytes);
        var entropy = CreateBlob(Entropy);
        DATA_BLOB dataOut = default;
        IntPtr description = IntPtr.Zero;
        try
        {
            if (!CryptUnprotectData(ref dataIn, out description, ref entropy, IntPtr.Zero, IntPtr.Zero, CryptProtectUiForbidden, out dataOut))
            {
                throw new InvalidDataException("DPAPIによる運用状態復号に失敗しました。別ユーザー、別PC、または改ざんの可能性があります。Win32Error=" + Marshal.GetLastWin32Error());
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

    private sealed class OperationalState
    {
        public int Version { get; set; }
        public int FailedUnlockCount { get; set; }
        public DateTime LockoutUntilUtc { get; set; }
        public DateTime UpdatedAtUtc { get; set; }
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
