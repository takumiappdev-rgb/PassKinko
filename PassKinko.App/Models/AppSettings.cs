using System;

namespace PassKinko.App.Models;

public sealed class AppSettings
{
    public bool IsInitialized { get; set; }

    // v10: マスターパスワードからPBKDF2で暗号鍵/HMAC鍵を導出するためのsalt。
    public string KdfSaltBase64 { get; set; } = string.Empty;

    // v10: saltの偶発的破損をパスワード不一致と誤認しないための公開チェックサム。
    public string KdfSaltChecksumBase64 { get; set; } = string.Empty;

    // v10: マスターパスワード検証用。マスターパスワード自体や復号可能な値は保存しない。
    public string MasterVerifierBase64 { get; set; } = string.Empty;

    // 旧開発版互換フィールド。v10では使用しない。
    public string MasterPasswordSaltBase64 { get; set; } = string.Empty;
    public string MasterPasswordHashBase64 { get; set; } = string.Empty;

    public DateTime MasterPasswordUpdatedAtUtc { get; set; }
    public int FailedUnlockCount { get; set; }
    public DateTime LockoutUntilUtc { get; set; }

    // v10: 失敗回数・ロックアウト期限は平文フィールドを信用せず、
    // DPAPI(CurrentUser)で保護した運用状態から読み戻す。
    public string OperationalStateProtectedBase64 { get; set; } = string.Empty;
    public bool InitializationRequired { get; set; }
    public string SecurityMessage { get; set; } = string.Empty;
    public int AutoLockSeconds { get; set; } = 180;
    public int PasswordRevealSeconds { get; set; } = 30;
    public int ClipboardClearSeconds { get; set; } = 30;
    public string WindowAnchor { get; set; } = "BottomLeft";

    // 旧開発版互換フィールド。v10では使用しない。
    public string IntegrityKeyProtectedBase64 { get; set; } = string.Empty;

    // v10: マスターパスワード由来HMAC鍵で署名。KDF saltは公開KDFパラメータとして署名対象外。
    // 失敗回数/ロックアウト期限はOperationalStateProtectedBase64でDPAPI保護する。
    public string SettingsSignatureBase64 { get; set; } = string.Empty;

    // v20: Windows Hello 利用フラグ
    public bool UseWindowsHello { get; set; }
    public string WindowsHelloKeyProtectedBase64 { get; set; } = string.Empty;

    // v20: パスワード生成ルール
    public bool GenUseUpper { get; set; } = true;
    public bool GenUseDigits { get; set; } = true;
    public bool GenUseSymbols { get; set; } = true;
    public int GenLength { get; set; } = 10;

    // v20: 更新期限ルール (0: 無期限, 90: 90日, 365: 1年)
    public int MasterPasswordUpdateIntervalDays { get; set; }
}
