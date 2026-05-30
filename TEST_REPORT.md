# パス金庫 v10.2 リリース候補 確認レポート

## この環境で実施済み

- ZIP構成確認
- XAML XML構文確認
- C#ソースの括弧対応確認
- 未閉じ文字列の簡易検査
- 旧v10文書混入の整理
- ローカルデータ・テストデータ未同梱確認

## この環境で未実施

- Windows/WPF実機起動
- dotnet build
- DPAPI実機復旧確認
- GUI操作確認

## Windows側で確認してほしいこと

```powershell
.\run_dev.bat
```

起動後、初回設定、追加、検索、詳細表示、ロック、バックアップ作成、バックアップ復元、退避して新規開始を確認してください。


## v10.2.1 / V001.000.000 リリース前更新

- build_release.bat を PublishSingleFile 不使用の Release build + RELEASEコピー方式へ変更。
- ロック解除画面右下へ `V001.000.000` 表示を追加。
- .csproj に FileVersion / AssemblyVersion / InformationalVersion を設定。
