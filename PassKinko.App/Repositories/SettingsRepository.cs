using System;
using System.Globalization;
using System.IO;
using System.Text;
using System.Text.Json;
using PassKinko.App.Models;
using PassKinko.App.Security;
using PassKinko.App.Utilities;

namespace PassKinko.App.Repositories;

public sealed class SettingsRepository
{
    private readonly MasterPasswordService _masterPasswordService;
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    public SettingsRepository(MasterPasswordService masterPasswordService)
    {
        _masterPasswordService = masterPasswordService;
    }

    public AppSettings Load()
    {
        AppPaths.EnsureDirectories();
        if (!File.Exists(AppPaths.SettingsPath)) return new AppSettings();

        try
        {
            var json = File.ReadAllText(AppPaths.SettingsPath);
            return JsonSerializer.Deserialize<AppSettings>(json) ?? new AppSettings();
        }
        catch
        {
            return new AppSettings
            {
                IsInitialized = true,
                InitializationRequired = true,
                SecurityMessage = "設定ファイルを読み込めません。破損または改ざんの可能性があります。安全のため利用を停止します。バックアップから復元してください。"
            };
        }
    }

    public void Save(AppSettings settings, CryptoKeys? keys = null)
    {
        SaveToPath(settings, AppPaths.SettingsPath, keys);
    }

    public void SaveToPath(AppSettings settings, string path, CryptoKeys? keys = null)
    {
        AppPaths.EnsureDirectories();
        if (settings.IsInitialized && keys != null)
        {
            settings.SettingsSignatureBase64 = _masterPasswordService.SignSettings(settings, keys);
        }

        var json = JsonSerializer.Serialize(settings, JsonOptions);
        AtomicWriteText(path, json, new UTF8Encoding(false));
    }

    public void MarkInitializationRequired(AppSettings settings, string message, CryptoKeys? keys = null)
    {
        settings.IsInitialized = true;
        settings.InitializationRequired = true;
        settings.SecurityMessage = message;
        Save(settings, keys);
    }

    public void Reset()
    {
        if (File.Exists(AppPaths.SettingsPath)) File.Delete(AppPaths.SettingsPath);
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
}
