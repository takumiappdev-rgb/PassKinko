using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using PassKinko.App.Models;
using PassKinko.App.Security;
using PassKinko.App.Utilities;

namespace PassKinko.App.Repositories;

public sealed class CredentialRepository
{
    private readonly VaultCryptoService _crypto;
    private readonly Func<CryptoKeys> _keysProvider;
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };
    private static readonly JsonSerializerOptions CompactJsonOptions = new() { WriteIndented = false };

    public CredentialRepository(VaultCryptoService crypto, Func<CryptoKeys> keysProvider)
    {
        _crypto = crypto;
        _keysProvider = keysProvider;
    }

    public void InitializeEmptyVault()
    {
        if (File.Exists(AppPaths.DatabasePath))
        {
            _ = LoadVault();
            return;
        }

        SaveVault(new VaultFile());
    }

    public void ValidateVaultOrThrow()
    {
        _ = LoadVault();
    }

    public IReadOnlyList<CredentialSummary> GetSummaries()
    {
        var vault = LoadVault();
        return vault.Items
            .Select(x =>
            {
                var website = _crypto.DecryptString(x.WebsiteEnc, _keysProvider());
                var websites = DecryptWebsites(x, website);
                return new CredentialSummary
                {
                    Id = x.Id,
                    ServiceName = _crypto.DecryptString(x.ServiceNameEnc, _keysProvider()),
                    Website = websites.FirstOrDefault() ?? website,
                    Websites = websites,
                    Username = _crypto.DecryptString(x.UsernameEnc, _keysProvider()),
                    Memo = _crypto.DecryptString(x.MemoEnc, _keysProvider()),
                    UpdatedAt = x.UpdatedAt
                };
            })
            .OrderByDescending(x => x.UpdatedAt)
            .ThenBy(x => x.ServiceName)
            .ToList();
    }

    public CredentialItem GetById(long id)
    {
        var vault = LoadVault();
        var x = vault.Items.FirstOrDefault(i => i.Id == id)
            ?? throw new InvalidDataException("指定された資格情報が見つかりません。削除または破損の可能性があります。");
        return FromVaultCredential(x);
    }

    public IReadOnlyList<CredentialItem> GetAll()
    {
        var vault = LoadVault();
        return vault.Items
            .Select(FromVaultCredential)
            .OrderByDescending(x => x.UpdatedAt)
            .ThenBy(x => x.ServiceName)
            .ToList();
    }

    public void ReplaceAll(IEnumerable<CredentialItem> items)
    {
        var vault = BuildVault(items, _keysProvider());
        SaveVault(vault);
    }

    public void WriteAllToPath(IEnumerable<CredentialItem> items, string path, CryptoKeys keys)
    {
        var vault = BuildVault(items, keys);
        SaveVaultToPath(vault, path, keys);
    }

    public void ValidateVaultAtPath(string path, CryptoKeys keys)
    {
        _ = LoadVaultFromPath(path, keys);
    }

    public void Upsert(CredentialItem item)
    {
        var vault = LoadVault();
        var now = DateTime.UtcNow;
        var existing = vault.Items.FirstOrDefault(x => x.Id == item.Id);

        if (existing == null)
        {
            existing = new VaultCredential
            {
                Id = vault.NextId++,
                CreatedAt = now
            };
            vault.Items.Add(existing);
        }

        existing.ServiceNameEnc = _crypto.EncryptString(item.ServiceName.Trim(), _keysProvider());
        var websites = NormalizeWebsites(item);
        existing.WebsiteEnc = _crypto.EncryptString(websites.FirstOrDefault() ?? string.Empty, _keysProvider());
        existing.WebsitesJsonEnc = _crypto.EncryptString(JsonSerializer.Serialize(websites, CompactJsonOptions), _keysProvider());
        existing.UsernameEnc = _crypto.EncryptString(item.Username.Trim(), _keysProvider());
        existing.PasswordEnc = _crypto.EncryptString(item.Password, _keysProvider());
        existing.MemoEnc = _crypto.EncryptString(item.Memo.Trim(), _keysProvider());
        existing.UpdatedAt = now;

        SaveVault(vault);
    }

    public void Delete(long id)
    {
        var vault = LoadVault();
        vault.Items.RemoveAll(x => x.Id == id);
        SaveVault(vault);
    }

    public void ResetAll()
    {
        if (File.Exists(AppPaths.DatabasePath)) File.Delete(AppPaths.DatabasePath);
    }

    public string ExportCsv(string outputPath)
    {
        var items = GetAll();
        var sb = new StringBuilder();
        sb.AppendLine("サービス名,ウェブサイト,ユーザー名,パスワード,メモ,作成日,更新日");
        foreach (var item in items)
        {
            sb.AppendLine(string.Join(",", new[]
            {
                Csv(item.ServiceName),
                Csv(string.Join("; ", NormalizeWebsites(item))),
                Csv(item.Username),
                Csv(item.Password),
                Csv(item.Memo),
                Csv(ToLocalText(item.CreatedAt)),
                Csv(ToLocalText(item.UpdatedAt))
            }));
        }
        AtomicWriteText(outputPath, sb.ToString(), new UTF8Encoding(true));
        return outputPath;
    }

    public string ExportPortableBackup(string outputPath, AppSettings settings)
    {
        AppPaths.EnsureDirectories();
        if (!File.Exists(AppPaths.DatabasePath))
        {
            throw new FileNotFoundException("資格情報データが存在しないため、バックアップを作成できません。", AppPaths.DatabasePath);
        }
        if (!File.Exists(AppPaths.SettingsPath))
        {
            throw new FileNotFoundException("設定ファイルが存在しないため、バックアップを作成できません。", AppPaths.SettingsPath);
        }

        // 出力前に現行DBを検証して、破損DBを成功扱いで保存しない。
        ValidateVaultOrThrow();

        var vaultJson = File.ReadAllText(AppPaths.DatabasePath);
        var rawSettingsJson = File.ReadAllText(AppPaths.SettingsPath);
        if (string.IsNullOrWhiteSpace(vaultJson) || string.IsNullOrWhiteSpace(rawSettingsJson))
        {
            throw new InvalidDataException("バックアップに必要なファイルが空です。");
        }

        var settingsForBackup = JsonSerializer.Deserialize<AppSettings>(rawSettingsJson) ?? settings;
        // DPAPIで保護した運用状態はPC/Windowsユーザーに依存するため、ポータブルバックアップには含めない。
        // 復元先では正しいマスターパスワード入力後に再構築する。
        settingsForBackup.OperationalStateProtectedBase64 = string.Empty;
        settingsForBackup.FailedUnlockCount = 0;
        settingsForBackup.LockoutUntilUtc = default;
        var settingsJson = JsonSerializer.Serialize(settingsForBackup, JsonOptions);

        var backup = new PortableBackupFile
        {
            Format = "PassKinkoPortableBackup",
            Version = 102,
            CreatedAtUtc = DateTime.UtcNow,
            Note = "settings.json と暗号化済みDBを含むポータブルバックアップです。復元後は運用状態を復元先PCで再構築します。",
            SettingsJsonBase64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(settingsJson)),
            VaultJsonBase64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(vaultJson))
        };
        AtomicWriteText(outputPath, JsonSerializer.Serialize(backup, JsonOptions), new UTF8Encoding(true));
        return outputPath;
    }

    public void RestorePortableBackup(string inputPath)
    {
        if (!File.Exists(inputPath)) throw new FileNotFoundException("バックアップファイルが見つかりません。", inputPath);
        var json = File.ReadAllText(inputPath);
        var backup = JsonSerializer.Deserialize<PortableBackupFile>(json)
            ?? throw new InvalidDataException("バックアップファイルを読み込めません。");
        if (backup.Format != "PassKinkoPortableBackup" || backup.Version < 102)
        {
            throw new InvalidDataException("未対応のバックアップ形式です。");
        }
        if (string.IsNullOrWhiteSpace(backup.SettingsJsonBase64) || string.IsNullOrWhiteSpace(backup.VaultJsonBase64))
        {
            throw new InvalidDataException("バックアップに必要な情報が不足しています。");
        }

        var settingsJson = Encoding.UTF8.GetString(Convert.FromBase64String(backup.SettingsJsonBase64));
        var vaultJson = Encoding.UTF8.GetString(Convert.FromBase64String(backup.VaultJsonBase64));
        if (string.IsNullOrWhiteSpace(settingsJson) || string.IsNullOrWhiteSpace(vaultJson))
        {
            throw new InvalidDataException("バックアップ内のデータが空です。");
        }

        AtomicWriteText(AppPaths.SettingsPath, settingsJson, new UTF8Encoding(false));
        AtomicWriteText(AppPaths.DatabasePath, vaultJson, new UTF8Encoding(false));
    }

    private VaultFile BuildVault(IEnumerable<CredentialItem> items, CryptoKeys keys)
    {
        var vault = new VaultFile();
        foreach (var item in items)
        {
            var newItem = new CredentialItem
            {
                Id = vault.NextId++,
                ServiceName = item.ServiceName,
                Website = item.Website,
                Websites = NormalizeWebsites(item),
                Username = item.Username,
                Password = item.Password,
                Memo = item.Memo,
                CreatedAt = item.CreatedAt == default ? DateTime.UtcNow : item.CreatedAt,
                UpdatedAt = item.UpdatedAt == default ? DateTime.UtcNow : item.UpdatedAt
            };
            vault.Items.Add(ToVaultCredential(newItem, keys));
        }
        return vault;
    }

    private CredentialItem FromVaultCredential(VaultCredential x)
    {
        var website = _crypto.DecryptString(x.WebsiteEnc, _keysProvider());
        var websites = DecryptWebsites(x, website);
        return new CredentialItem
        {
            Id = x.Id,
            ServiceName = _crypto.DecryptString(x.ServiceNameEnc, _keysProvider()),
            Website = websites.FirstOrDefault() ?? website,
            Websites = websites,
            Username = _crypto.DecryptString(x.UsernameEnc, _keysProvider()),
            Password = _crypto.DecryptString(x.PasswordEnc, _keysProvider()),
            Memo = _crypto.DecryptString(x.MemoEnc, _keysProvider()),
            CreatedAt = x.CreatedAt,
            UpdatedAt = x.UpdatedAt
        };
    }

    private VaultFile LoadVault() => LoadVaultFromPath(AppPaths.DatabasePath, _keysProvider());

    private VaultFile LoadVaultFromPath(string path, CryptoKeys keys)
    {
        AppPaths.EnsureDirectories();
        if (!File.Exists(path))
        {
            throw new FileNotFoundException("資格情報データが見つかりません。削除、破損、または改ざんの可能性があります。", path);
        }

        var json = File.ReadAllText(path);
        var vault = JsonSerializer.Deserialize<VaultFile>(json)
            ?? throw new InvalidDataException("資格情報データを読み込めません。破損または改ざんの可能性があります。");

        var actual = SignVault(vault, keys);
        var legacyActual = SignVault(vault, keys, includeWebsitesJson: false);
        if (!VerifySignature(vault.SignatureBase64, actual) && !VerifySignature(vault.SignatureBase64, legacyActual))
        {
            throw new InvalidDataException("資格情報データの改ざん、破損、ロールバック、またはマスターパスワード不一致を検知しました。");
        }

        return vault;
    }

    private void SaveVault(VaultFile vault)
    {
        SaveVaultToPath(vault, AppPaths.DatabasePath, _keysProvider());
    }

    private void SaveVaultToPath(VaultFile vault, string path, CryptoKeys keys)
    {
        AppPaths.EnsureDirectories();
        vault.SignatureBase64 = SignVault(vault, keys);
        var json = JsonSerializer.Serialize(vault, JsonOptions);
        AtomicWriteText(path, json, new UTF8Encoding(false));
    }

    private VaultCredential ToVaultCredential(CredentialItem item) => ToVaultCredential(item, _keysProvider());

    private VaultCredential ToVaultCredential(CredentialItem item, CryptoKeys keys) => new()
    {
        Id = item.Id,
        ServiceNameEnc = _crypto.EncryptString(item.ServiceName.Trim(), keys),
        WebsiteEnc = _crypto.EncryptString(NormalizeWebsites(item).FirstOrDefault() ?? string.Empty, keys),
        WebsitesJsonEnc = _crypto.EncryptString(JsonSerializer.Serialize(NormalizeWebsites(item), CompactJsonOptions), keys),
        UsernameEnc = _crypto.EncryptString(item.Username.Trim(), keys),
        PasswordEnc = _crypto.EncryptString(item.Password, keys),
        MemoEnc = _crypto.EncryptString(item.Memo.Trim(), keys),
        CreatedAt = item.CreatedAt,
        UpdatedAt = item.UpdatedAt
    };

    private string SignVault(VaultFile vault) => SignVault(vault, _keysProvider());

    private string SignVault(VaultFile vault, CryptoKeys keys, bool includeWebsitesJson = true)
    {
        object payload = includeWebsitesJson
            ? new
            {
                vault.NextId,
                Items = vault.Items.Select(x => new
                {
                    x.Id,
                    x.ServiceNameEnc,
                    x.WebsiteEnc,
                    x.WebsitesJsonEnc,
                    x.UsernameEnc,
                    x.PasswordEnc,
                    x.MemoEnc,
                    x.CreatedAt,
                    x.UpdatedAt
                }).ToList()
            }
            : new
            {
                vault.NextId,
                Items = vault.Items.Select(x => new
                {
                    x.Id,
                    x.ServiceNameEnc,
                    x.WebsiteEnc,
                    x.UsernameEnc,
                    x.PasswordEnc,
                    x.MemoEnc,
                    x.CreatedAt,
                    x.UpdatedAt
                }).ToList()
            };
        var json = JsonSerializer.Serialize(payload, CompactJsonOptions);
        using var hmac = new HMACSHA256(keys.MacKey);
        return Convert.ToBase64String(hmac.ComputeHash(Encoding.UTF8.GetBytes(json)));
    }

    private List<string> DecryptWebsites(VaultCredential credential, string fallbackWebsite)
    {
        if (!string.IsNullOrWhiteSpace(credential.WebsitesJsonEnc))
        {
            try
            {
                var json = _crypto.DecryptString(credential.WebsitesJsonEnc, _keysProvider());
                var values = JsonSerializer.Deserialize<List<string>>(json) ?? new List<string>();
                var normalized = NormalizeWebsites(values);
                if (normalized.Count > 0) return normalized;
            }
            catch
            {
                // Fall back to the legacy single URL field so older data remains usable.
            }
        }

        return NormalizeWebsites(new[] { fallbackWebsite });
    }

    private static List<string> NormalizeWebsites(CredentialItem item)
    {
        var values = item.Websites.Count > 0 ? item.Websites : new List<string> { item.Website };
        return NormalizeWebsites(values);
    }

    private static List<string> NormalizeWebsites(IEnumerable<string> values)
    {
        return values
            .Select(x => (x ?? string.Empty).Trim())
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(10)
            .ToList();
    }

    private static bool VerifySignature(string expectedBase64, string actualBase64)
    {
        if (string.IsNullOrWhiteSpace(expectedBase64) || string.IsNullOrWhiteSpace(actualBase64)) return false;
        try
        {
            var expected = Convert.FromBase64String(expectedBase64);
            var actual = Convert.FromBase64String(actualBase64);
            return expected.Length == actual.Length && CryptographicOperations.FixedTimeEquals(expected, actual);
        }
        catch
        {
            return false;
        }
    }

    private static string Csv(string value)
    {
        value ??= string.Empty;
        var sanitized = value.Replace("\r", " ").Replace("\n", " ");
        var firstMeaningful = sanitized.TrimStart(' ', '\t');
        if (firstMeaningful.Length > 0 && (firstMeaningful[0] == '=' || firstMeaningful[0] == '+' || firstMeaningful[0] == '-' || firstMeaningful[0] == '@'))
        {
            sanitized = "'" + sanitized;
        }
        return '"' + sanitized.Replace("\"", "\"\"") + '"';
    }

    private static void AtomicWriteText(string path, string text, Encoding encoding)
    {
        var directory = Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(directory)) Directory.CreateDirectory(directory);
        var temp = path + ".tmp_" + Guid.NewGuid().ToString("N");
        try
        {
            using (var stream = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            using (var writer = new StreamWriter(stream, encoding))
            {
                writer.Write(text);
                writer.Flush();
                stream.Flush(true);
            }
            if (File.Exists(path)) File.Replace(temp, path, null, true);
            else File.Move(temp, path);
        }
        finally
        {
            if (File.Exists(temp)) File.Delete(temp);
        }
    }

    private static string ToLocalText(DateTime utc)
    {
        if (utc == default) return string.Empty;
        return utc.ToLocalTime().ToString("yyyy/MM/dd HH:mm", CultureInfo.InvariantCulture);
    }

    private sealed class PortableBackupFile
    {
        public string Format { get; set; } = string.Empty;
        public int Version { get; set; }
        public DateTime CreatedAtUtc { get; set; }
        public string Note { get; set; } = string.Empty;
        public string SettingsJsonBase64 { get; set; } = string.Empty;
        public string VaultJsonBase64 { get; set; } = string.Empty;
    }

    private sealed class VaultFile
    {
        public int Version { get; set; } = 10;
        public long NextId { get; set; } = 1;
        public List<VaultCredential> Items { get; set; } = new();
        public string SignatureBase64 { get; set; } = string.Empty;
    }

    private sealed class VaultCredential
    {
        public long Id { get; set; }
        public string ServiceNameEnc { get; set; } = string.Empty;
        public string WebsiteEnc { get; set; } = string.Empty;
        public string WebsitesJsonEnc { get; set; } = string.Empty;
        public string UsernameEnc { get; set; } = string.Empty;
        public string PasswordEnc { get; set; } = string.Empty;
        public string MemoEnc { get; set; } = string.Empty;
        public DateTime CreatedAt { get; set; }
        public DateTime UpdatedAt { get; set; }
    }
}
