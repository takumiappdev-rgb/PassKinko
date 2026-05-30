using System;
using System.IO;
namespace PassKinko.App.Utilities;

public static class AppPaths
{
    public static string AppDataDirectory => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "PassKinko");

    // 開発版は外部NuGet依存を避けるため、暗号化済みJSONを .db 名で保存します。
    // 最終配布版でSQLite化する場合も、このパスを引き継げます。
    public static string DatabasePath => Path.Combine(AppDataDirectory, "passkinko.db");

    public static string SettingsPath => Path.Combine(AppDataDirectory, "settings.json");

    public static void EnsureDirectories()
    {
        Directory.CreateDirectory(AppDataDirectory);
    }
}
