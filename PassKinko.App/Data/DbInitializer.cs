using System.IO;
using PassKinko.App.Utilities;

namespace PassKinko.App.Data;

// 開発版では外部NuGetに依存しないため、SQLite初期化は使いません。
// データ保存先ディレクトリの作成だけを担当します。
public sealed class DbInitializer
{
    public void Initialize() => AppPaths.EnsureDirectories();

    public void ResetAll()
    {
        if (File.Exists(AppPaths.DatabasePath)) File.Delete(AppPaths.DatabasePath);
        if (File.Exists(AppPaths.SettingsPath)) File.Delete(AppPaths.SettingsPath);
    }
}
