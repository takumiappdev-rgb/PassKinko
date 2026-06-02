# GitHub リポジトリ設定メモ V002.000.000

このメモは、GitHub上の `takumiappdev-rgb/PassKinko` を V002.000.000 向けに整えるための設定メモです。

## About 欄

GitHubのリポジトリ右側にある About は、READMEとは別管理です。
リポジトリ画面右側の歯車アイコンから、以下を設定してください。

Description:

```text
ローカルPC上で資格情報を管理するWindows向けパスワード管理ツール
```

Website:

```text

```

Topics:

```text
windows
wpf
csharp
dotnet
password-manager
local-first
security
```

チェック推奨:

```text
Releases
Packages は未使用で問題ありません
```

## Release 作成時の設定

Tag:

```text
V002.000.000
```

Target:

```text
main
```

Release title:

```text
パス金庫 V002.000.000
```

Release notes:

```text
DOCUMENT\GITHUB_RELEASE_BODY_V002.000.000.md
```

Assets に添付するファイル:

```text
PassKinko_V002.000.000_Windows.zip
```

GitHubが自動表示する `Source code (zip)` と `Source code (tar.gz)` は、開発者向けの自動生成ファイルです。
一般ユーザー向けには `PassKinko_V002.000.000_Windows.zip` を案内してください。

## GitHubへ反映するコマンド

PassKinko側のフォルダで実行します。

```powershell
cd "E:\GitHub\パス金庫\PassKinko"
git status --short
git add README.md LICENSE PRIVACY_POLICY.md DOCUMENT\GITHUB_RELEASE_BODY_V002.000.000.md DOCUMENT\GITHUB_REPOSITORY_SETTINGS_V002.000.000.md
git commit -m "Update GitHub docs for V002.000.000"
git push
```

以下のファイルは、内部メモ色が強いため、GitHubへ載せる前に内容確認してください。

```text
PassKinko_HANDOVER_V002.md
requirements_V002.md
```
