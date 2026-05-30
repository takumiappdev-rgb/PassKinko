using System;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using PassKinko.App.Models;

namespace PassKinko.App.Security;

public sealed class MasterPasswordService
{
    public const int MinLength = 8;
    public const int MaxLength = 64;
    private const int SaltSize = 32;
    private const int KeyMaterialSize = 64;
    private const int Iterations = 600_000;
    private static readonly byte[] VerifierPayload = Encoding.UTF8.GetBytes("PassKinko.MasterVerifier.v10");
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = false };

    public AppSettings CreateInitialSettings(string masterPassword)
    {
        var salt = RandomNumberGenerator.GetBytes(SaltSize);
        using var keys = DeriveKeys(masterPassword, salt);

        return new AppSettings
        {
            IsInitialized = true,
            KdfSaltBase64 = Convert.ToBase64String(salt),
            KdfSaltChecksumBase64 = ComputeSaltChecksum(salt),
            MasterVerifierBase64 = ComputeVerifier(keys),
            MasterPasswordUpdatedAtUtc = DateTime.UtcNow,
            FailedUnlockCount = 0,
            LockoutUntilUtc = default,
            InitializationRequired = false,
            SecurityMessage = string.Empty,
            AutoLockSeconds = 180,
            PasswordRevealSeconds = 30,
            ClipboardClearSeconds = 30,
            WindowAnchor = "BottomLeft"
        };
    }

    public CryptoKeys DeriveKeys(string masterPassword, AppSettings settings)
    {
        if (string.IsNullOrWhiteSpace(settings.KdfSaltBase64))
        {
            throw new InvalidOperationException("マスターパスワード鍵導出用saltが存在しません。v10形式の設定が必要です。");
        }
        return DeriveKeys(masterPassword, Convert.FromBase64String(settings.KdfSaltBase64));
    }

    public string? ValidateKdfParameters(AppSettings settings)
    {
        if (string.IsNullOrWhiteSpace(settings.KdfSaltBase64)) return "KDF saltが存在しません。";
        try
        {
            var salt = Convert.FromBase64String(settings.KdfSaltBase64);
            if (salt.Length != SaltSize) return "KDF saltの長さが不正です。";
            if (!string.IsNullOrWhiteSpace(settings.KdfSaltChecksumBase64) &&
                !FixedTimeEqualsBase64(settings.KdfSaltChecksumBase64, ComputeSaltChecksum(salt)))
            {
                return "KDF saltの破損を検知しました。";
            }
            return null;
        }
        catch
        {
            return "KDF saltがBase64として不正です。";
        }
    }

    public bool Verify(string masterPassword, AppSettings settings)
    {
        if (string.IsNullOrWhiteSpace(settings.KdfSaltBase64) || string.IsNullOrWhiteSpace(settings.MasterVerifierBase64))
        {
            return false;
        }

        if (ValidateKdfParameters(settings) != null)
        {
            return false;
        }

        try
        {
            using var keys = DeriveKeys(masterPassword, settings);
            var actual = ComputeVerifier(keys);
            return FixedTimeEqualsBase64(settings.MasterVerifierBase64, actual);
        }
        catch
        {
            return false;
        }
    }

    public string SignSettings(AppSettings settings, CryptoKeys keys)
    {
        var payload = new
        {
            settings.IsInitialized,
            settings.MasterVerifierBase64,
            settings.KdfSaltChecksumBase64,
            settings.MasterPasswordUpdatedAtUtc,
            settings.InitializationRequired,
            settings.SecurityMessage,
            settings.AutoLockSeconds,
            settings.PasswordRevealSeconds,
            settings.ClipboardClearSeconds,
            settings.WindowAnchor
        };
        return SignObject(payload, keys.MacKey);
    }

    public bool VerifySettingsSignature(AppSettings settings, CryptoKeys keys)
    {
        if (!settings.IsInitialized) return true;
        if (string.IsNullOrWhiteSpace(settings.SettingsSignatureBase64)) return false;
        return FixedTimeEqualsBase64(settings.SettingsSignatureBase64, SignSettings(settings, keys));
    }

    public void UpdateMasterPassword(AppSettings settings, string newMasterPassword)
    {
        var salt = RandomNumberGenerator.GetBytes(SaltSize);
        using var keys = DeriveKeys(newMasterPassword, salt);
        settings.KdfSaltBase64 = Convert.ToBase64String(salt);
        settings.KdfSaltChecksumBase64 = ComputeSaltChecksum(salt);
        settings.MasterVerifierBase64 = ComputeVerifier(keys);
        settings.MasterPasswordUpdatedAtUtc = DateTime.UtcNow;
        settings.FailedUnlockCount = 0;
        settings.LockoutUntilUtc = default;
        settings.InitializationRequired = false;
        settings.SecurityMessage = string.Empty;
    }

    public bool IsPasswordExpired(AppSettings settings)
    {
        if (!settings.IsInitialized || settings.MasterPasswordUpdatedAtUtc == default) return false;
        return DateTime.UtcNow - settings.MasterPasswordUpdatedAtUtc >= TimeSpan.FromDays(365);
    }

    private static CryptoKeys DeriveKeys(string password, byte[] salt)
    {
        var material = Rfc2898DeriveBytes.Pbkdf2(
            password,
            salt,
            Iterations,
            HashAlgorithmName.SHA256,
            KeyMaterialSize);

        var encryptionKey = new byte[32];
        var macKey = new byte[32];
        Buffer.BlockCopy(material, 0, encryptionKey, 0, 32);
        Buffer.BlockCopy(material, 32, macKey, 0, 32);
        CryptographicOperations.ZeroMemory(material);
        return new CryptoKeys(encryptionKey, macKey);
    }

    private static string ComputeSaltChecksum(byte[] salt)
    {
        return Convert.ToBase64String(SHA256.HashData(salt));
    }

    private static string ComputeVerifier(CryptoKeys keys)
    {
        using var hmac = new HMACSHA256(keys.MacKey);
        return Convert.ToBase64String(hmac.ComputeHash(VerifierPayload));
    }

    private static string SignObject(object payload, byte[] key)
    {
        var json = JsonSerializer.Serialize(payload, JsonOptions);
        using var hmac = new HMACSHA256(key);
        return Convert.ToBase64String(hmac.ComputeHash(Encoding.UTF8.GetBytes(json)));
    }

    private static bool FixedTimeEqualsBase64(string leftBase64, string rightBase64)
    {
        try
        {
            var left = Convert.FromBase64String(leftBase64);
            var right = Convert.FromBase64String(rightBase64);
            return left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
        }
        catch
        {
            return false;
        }
    }
}
