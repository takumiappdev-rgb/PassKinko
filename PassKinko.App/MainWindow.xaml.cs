using System;
using System.Collections.Generic;
using System.Globalization;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;
using Microsoft.Win32;
using PassKinko.App.Models;
using PassKinko.App.Repositories;
using PassKinko.App.Security;
using PassKinko.App.Services;
using PassKinko.App.Utilities;

namespace PassKinko.App;

public partial class MainWindow : Window
{
    private const int MasterPasswordMaxLength = MasterPasswordService.MaxLength;
    private const string ProgramVersion = "V001.000.000";
    private const string SecretMask = "●●●●●●●●";

    private readonly VaultCryptoService _crypto = new();
    private readonly MasterPasswordService _masterPasswordService = new();
    private readonly OperationalStateService _operationalStateService = new();
    private readonly ClipboardService _clipboard = new();
    private readonly DispatcherTimer _autoLockTimer = new();
    private readonly DispatcherTimer _revealTimer = new();
    private readonly DispatcherTimer _statusTimer = new();

    private SettingsRepository _settingsRepository = null!;
    private CredentialRepository _credentialRepository = null!;
    private TrayService? _tray;
    private AppSettings _settings = new();
    private DateTime _lastActivity = DateTime.UtcNow;
    private bool _isUnlocked;
    private bool _isCriticalScreen;
    private bool _isExitRequested;
    private CryptoKeys? _activeKeys;
    private bool _operationalStateRecoveryRequired;
    private string _operationalStateRecoveryMessage = string.Empty;
    private readonly TimeSpan _operationalStateRecoveryDelay = TimeSpan.FromMinutes(5);
    private Stopwatch? _operationalStateRecoveryStopwatch;

    private CredentialItem? _currentDetail;
    private PasswordInput? _unlockPasswordInput;
    private TextBox? _searchBox;
    private ListBox? _listBox;
    private TextBlock? _detailUsernameText;
    private TextBlock? _detailPasswordText;
    private Button? _detailUsernameRevealButton;
    private Button? _detailPasswordRevealButton;
    private bool _usernameRevealed;
    private bool _passwordRevealed;
    private long? _pendingDeleteId;
    private DateTime _pendingDeleteExpiresUtc;

    private enum StatusKind
    {
        Info,
        Success,
        Warning,
        Error
    }

    public MainWindow()
    {
        InitializeComponent();
        WindowPositionService.MoveToBottomLeft(this);

        Loaded += MainWindow_Loaded;
        Closing += (_, e) =>
        {
            if (_isExitRequested) return;

            e.Cancel = true;
            LockForHiddenState();
            Hide();
        };

        StateChanged += (_, _) =>
        {
            if (WindowState == WindowState.Minimized)
            {
                LockForHiddenState();
                Hide();
            }
        };

        PreviewMouseMove += (_, _) => MarkActivity();
        PreviewMouseDown += (_, _) => MarkActivity();
        PreviewKeyDown += (_, _) => MarkActivity();
    }

    public void RequestApplicationExit()
    {
        _isExitRequested = true;
        _clipboard.ClearIfUnchanged();
        _tray?.Dispose();
    }

    private void MainWindow_Loaded(object sender, RoutedEventArgs e)
    {
        AppPaths.EnsureDirectories();
        _settingsRepository = new SettingsRepository(_masterPasswordService);
        _settings = _settingsRepository.Load();
        if (_settings.IsInitialized && !_settings.InitializationRequired)
        {
            try
            {
                _operationalStateService.LoadInto(_settings);
            }
            catch (Exception ex)
            {
                _operationalStateRecoveryRequired = true;
                _operationalStateRecoveryMessage = "環境移行、または運用状態保護データの欠落・破損を検知しました。安全のため一定時間待機後、正しいマスターパスワードで運用状態を再構築します。詳細: " + ex.Message;
                _operationalStateRecoveryStopwatch = Stopwatch.StartNew();
                _settings.FailedUnlockCount = 0;
                _settings.LockoutUntilUtc = default;
            }
        }
        _credentialRepository = new CredentialRepository(_crypto, GetActiveKeys);
        _tray ??= new TrayService(this, LockNow);

        _autoLockTimer.Interval = TimeSpan.FromSeconds(5);
        _autoLockTimer.Tick += (_, _) =>
        {
            if (_isUnlocked && (DateTime.UtcNow - _lastActivity).TotalSeconds >= _settings.AutoLockSeconds)
            {
                LockNow();
            }
        };
        _autoLockTimer.Start();

        _revealTimer.Tick += (_, _) => HideRevealedSecrets();
        _statusTimer.Tick += (_, _) =>
        {
            _statusTimer.Stop();
            StatusTextBlock.Text = string.Empty;
        };

        RouteStartup();
    }

    private void RouteStartup()
    {
        if (!_settings.IsInitialized)
        {
            var settingsFileExists = File.Exists(AppPaths.SettingsPath);
            var databaseFileExists = File.Exists(AppPaths.DatabasePath);
            var looksLikeTamperedSettings = databaseFileExists ||
                (settingsFileExists &&
                 (!string.IsNullOrWhiteSpace(_settings.KdfSaltBase64) ||
                  !string.IsNullOrWhiteSpace(_settings.MasterVerifierBase64) ||
                  !string.IsNullOrWhiteSpace(_settings.SettingsSignatureBase64)));

            if (looksLikeTamperedSettings)
            {
                ShowAccessBlocked("設定ファイルの未初期化状態への改ざん、欠落、または資格情報データとの不整合を検知しました。安全のためロック解除を停止します。バックアップから復元するか、不要であれば reset_local_data.bat で明示的に初期化してください。");
                return;
            }

            ShowFirstLaunch();
            return;
        }

        if (_settings.InitializationRequired)
        {
            ShowAccessBlocked(string.IsNullOrWhiteSpace(_settings.SecurityMessage)
                ? "安全のため通常利用を停止しています。"
                : _settings.SecurityMessage);
            return;
        }

        if (string.IsNullOrWhiteSpace(_settings.KdfSaltBase64) || string.IsNullOrWhiteSpace(_settings.MasterVerifierBase64))
        {
            ShowAccessBlocked("v10形式のマスターパスワード情報が存在しません。旧形式データ、または破損データのため通常利用を停止します。バックアップから復元するか、不要であれば reset_local_data.bat で明示的に初期化してください。");
            return;
        }

        var kdfError = _masterPasswordService.ValidateKdfParameters(_settings);
        if (kdfError != null)
        {
            ShowAccessBlocked("設定ファイルのKDFパラメータ破損を検知しました。" + kdfError + " 正しいマスターパスワードでも復号できない可能性があるため、バックアップから復元してください。");
            return;
        }

        try
        {
            // 資格情報データの検証はマスターパスワード入力後に実施する。
        }
        catch
        {
            // 起動時点では復号鍵がないため、ここでは通常のロック解除へ進める。
        }

        ShowUnlock();
    }

    private CryptoKeys GetActiveKeys()
    {
        if (_activeKeys == null)
        {
            throw new InvalidOperationException("マスターパスワードによるロック解除が必要です。");
        }
        return _activeKeys;
    }

    private void SaveSettings(CryptoKeys? keys = null)
    {
        if (_settings.IsInitialized)
        {
            _operationalStateService.ProtectInto(_settings);
        }
        _settingsRepository.Save(_settings, keys);
    }

    private void MarkInitializationRequired(string message, CryptoKeys? keys = null)
    {
        _settings.IsInitialized = true;
        _settings.InitializationRequired = true;
        _settings.SecurityMessage = message;
        SaveSettings(keys);
    }

    private void MarkActivity() => _lastActivity = DateTime.UtcNow;

    private void ResetRoot(string screenTitle)
    {
        HideRevealedSecrets();
        _pendingDeleteId = null;
        _pendingDeleteExpiresUtc = default;
        _detailUsernameRevealButton = null;
        _detailPasswordRevealButton = null;
        _isCriticalScreen = false;
        ScreenTitleTextBlock.Text = screenTitle;
        RootPanel.Children.Clear();
        SetStatus(string.Empty, 0);
    }

    private void ShowFirstLaunch()
    {
        _isUnlocked = false;
        ResetRoot("初回設定");

        AddDescription("マスターパスワードを設定します。忘れた場合、登録済みデータは復旧できません。");
        var master = AddPasswordInput("マスターパスワード", string.Empty, MasterPasswordMaxLength);
        var confirm = AddPasswordInput("確認入力", string.Empty, MasterPasswordMaxLength);
        AddHint("入力仕様：8〜64文字 / 空白のみ不可 / 推奨：長いパスフレーズまたは英字・数字・記号の組み合わせ");
        AddHint("標準仕様：3分無操作でロック / 表示・コピー内容は30秒で自動保護");

        var buttons = ButtonRow();
        var start = PrimaryButton("開始");
        start.Click += (_, _) =>
        {
            var master1 = NormalizeMasterPassword(master.Password);
            var master2 = NormalizeMasterPassword(confirm.Password);
            var validation = ValidateMasterPassword(master1);
            if (validation != null)
            {
                SetStatus(validation, 5, StatusKind.Error);
                return;
            }
            if (master1 != master2)
            {
                SetStatus("確認入力が一致しません。", 5, StatusKind.Error);
                return;
            }

            _settings = _masterPasswordService.CreateInitialSettings(master1);
            _activeKeys = _masterPasswordService.DeriveKeys(master1, _settings);
            SaveSettings(_activeKeys);
            _credentialRepository = new CredentialRepository(_crypto, GetActiveKeys);
            _credentialRepository.InitializeEmptyVault();
            _isUnlocked = true;
            MarkActivity();
            ShowSearch();
        };

        var cancel = SecondaryButton("閉じる");
        cancel.Click += (_, _) => Hide();
        buttons.Children.Add(start);
        buttons.Children.Add(cancel);
        RootPanel.Children.Add(buttons);
        master.Focus();
    }

    private void ShowUnlock()
    {
        _isUnlocked = false;
        ResetRoot("ロック解除");

        AddDescription("マスターパスワードを入力してください。");
        if (_operationalStateRecoveryRequired)
        {
            var remaining = GetOperationalRecoveryRemaining();
            AddWarning(_operationalStateRecoveryMessage + Environment.NewLine + "OS時刻変更では短縮できない待機時間を設けています。残り約 " + FormatRemaining(remaining) + " 後、正しいマスターパスワードを入力すると運用状態をこのPCで再構築します。登録済みデータは初期化しません。");
        }
        if (_settings.MasterPasswordUpdatedAtUtc != default)
        {
            AddHint("マスターパスワード更新日：" + ToLocalText(_settings.MasterPasswordUpdatedAtUtc) +
                    " / 次回更新期限：" + ToLocalDate(_settings.MasterPasswordUpdatedAtUtc.AddDays(365)));
        }
        _unlockPasswordInput = AddPasswordInput("マスターパスワード", string.Empty, MasterPasswordMaxLength);
        _unlockPasswordInput.KeyDown += (_, e) => { if (e.Key == Key.Enter) TryUnlock(); };
        AddHint("入力仕様：8〜64文字 / 空白のみ不可");

        RootPanel.Children.Add(new TextBlock
        {
            Text = $"失敗回数：{_settings.FailedUnlockCount} / 10",
            FontSize = 13,
            Foreground = _settings.FailedUnlockCount > 0 ? ErrorBrush() : Brushes.DimGray,
            Margin = new Thickness(0, 3, 0, 10)
        });

        var buttons = ButtonRow();
        var unlock = PrimaryButton("解除");
        unlock.Click += (_, _) => TryUnlock();
        var close = SecondaryButton("閉じる");
        close.Click += (_, _) => Hide();
        var startOver = SecondaryButton("新規開始");
        startOver.Click += (_, _) => ShowStartOverConfirm();
        buttons.Children.Add(unlock);
        buttons.Children.Add(close);
        buttons.Children.Add(startOver);
        RootPanel.Children.Add(buttons);
        if (_settings.LockoutUntilUtc > DateTime.UtcNow)
        {
            AddWarning("入力失敗が続いたため一時ロック中です。解除予定：" + ToLocalText(_settings.LockoutUntilUtc));
        }
        AddHint("10回連続で失敗すると、30分間ロックします。初期化によるデータ削除は行いません。");
        AddVersionStamp();
        _unlockPasswordInput.Focus();
    }

    private void TryUnlock()
    {
        if (_unlockPasswordInput == null) return;
        if (_settings.InitializationRequired)
        {
            ShowAccessBlocked(_settings.SecurityMessage);
            return;
        }

        if (_operationalStateRecoveryRequired)
        {
            var remaining = GetOperationalRecoveryRemaining();
            if (remaining > TimeSpan.Zero)
            {
                SetStatus("環境移行または運用状態破損を検知したため待機中です。残り約 " + FormatRemaining(remaining) + " です。", 8, StatusKind.Error);
                return;
            }
        }

        if (_settings.LockoutUntilUtc > DateTime.UtcNow)
        {
            SetStatus("一時ロック中です。解除予定：" + ToLocalText(_settings.LockoutUntilUtc), 8, StatusKind.Error);
            return;
        }

        var master = NormalizeMasterPassword(_unlockPasswordInput.Password);
        var validation = ValidateMasterPassword(master);
        if (validation != null)
        {
            SetStatus(validation, 5, StatusKind.Error);
            return;
        }

        if (_masterPasswordService.Verify(master, _settings))
        {
            _settings.FailedUnlockCount = 0;
            _settings.LockoutUntilUtc = default;
            _activeKeys = _masterPasswordService.DeriveKeys(master, _settings);
            if (!_masterPasswordService.VerifySettingsSignature(_settings, _activeKeys))
            {
                ShowAccessBlocked("設定ファイルの改ざん、破損、またはロールバックを検知しました。安全のためロック解除を停止します。バックアップから復元してください。");
                return;
            }

            try
            {
                _credentialRepository.ValidateVaultOrThrow();
            }
            catch (Exception ex)
            {
                ShowAccessBlocked("資格情報データの改ざん、破損、ロールバック、またはマスターパスワード不一致を検知しました。安全のためロック解除を停止します。バックアップから復元してください。詳細: " + ex.Message);
                return;
            }

            if (_operationalStateRecoveryRequired)
            {
                _operationalStateRecoveryRequired = false;
                _operationalStateRecoveryMessage = string.Empty;
                _operationalStateRecoveryStopwatch = null;
                _settings.FailedUnlockCount = 0;
                _settings.LockoutUntilUtc = default;
            }

            SaveSettings(_activeKeys);

            if (_masterPasswordService.IsPasswordExpired(_settings))
            {
                ShowMasterPasswordUpdate("マスターパスワードの更新期限を過ぎています。更新後に利用できます。");
                return;
            }

            _isUnlocked = true;
            MarkActivity();
            ShowSearch();
            return;
        }

        _settings.FailedUnlockCount++;
        if (_settings.FailedUnlockCount >= 10)
        {
            _settings.LockoutUntilUtc = DateTime.UtcNow.AddMinutes(30);
            _settings.FailedUnlockCount = 0;
            SaveSettings();
            ShowUnlock();
            SetStatus("マスターパスワードを10回間違えたため、30分間ロックします。", 8, StatusKind.Error);
            return;
        }

        SaveSettings();
        ShowUnlock();
        SetStatus("マスターパスワードが違います。残り " + (10 - _settings.FailedUnlockCount) + " 回です。", 5, StatusKind.Error);
    }

    private void ShowAccessBlocked(string reason)
    {
        _isUnlocked = false;
        ClearSensitiveState();
        _activeKeys?.Dispose();
        _activeKeys = null;
        ResetRoot("アクセス停止");
        _isCriticalScreen = true;

        AddWarning((string.IsNullOrWhiteSpace(reason) ? "安全のためロック解除を停止しています。" : reason) +
                   "\n\nこの画面ではデータ削除・初期化は行いません。バックアップから復元するか、利用者が明示的に reset_local_data.bat を実行して初期化してください。");

        var buttons = ButtonRow();
        var restore = SecondaryButton("バックアップ復元");
        restore.Width = 130;
        restore.Click += (_, _) => RestorePortableBackupFromDialog();
        var startOver = DangerButton("退避して新規開始");
        startOver.Width = 150;
        startOver.Click += (_, _) => ShowStartOverConfirm();
        var close = SecondaryButton("閉じる");
        close.Click += (_, _) => Hide();
        buttons.Children.Add(restore);
        buttons.Children.Add(startOver);
        buttons.Children.Add(close);
        RootPanel.Children.Add(buttons);
    }

    private void ShowSearch()
    {
        if (!_isUnlocked)
        {
            ShowUnlock();
            return;
        }

        ResetRoot("検索");
        _currentDetail = null;

        var top = new Grid { Margin = new Thickness(0, 0, 0, 10) };
        top.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        top.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        top.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

        _searchBox = new TextBox
        {
            Height = 34,
            FontSize = 14,
            Padding = new Thickness(8, 5, 8, 5),
            ToolTip = "サービス名 / URL / ユーザー名 / メモ"
        };
        _searchBox.TextChanged += (_, _) => LoadList(_searchBox.Text);
        top.Children.Add(_searchBox);

        var export = SecondaryButton("エクスポート");
        export.Width = 108;
        export.Margin = new Thickness(8, 0, 0, 0);
        export.Click += (_, _) => ShowExport();
        Grid.SetColumn(export, 1);
        top.Children.Add(export);

        var add = PrimaryButton("追加");
        add.Width = 76;
        add.Margin = new Thickness(8, 0, 0, 0);
        add.Click += (_, _) => ShowEdit(null);
        Grid.SetColumn(add, 2);
        top.Children.Add(add);
        RootPanel.Children.Add(top);

        _listBox = new ListBox
        {
            Height = 255,
            BorderBrush = new SolidColorBrush(Color.FromRgb(209, 213, 219)),
            BorderThickness = new Thickness(1),
            Background = Brushes.White
        };
        _listBox.MouseDoubleClick += (_, _) => OpenSelectedDetail();
        _listBox.KeyDown += (_, e) => { if (e.Key == Key.Enter) OpenSelectedDetail(); };
        RootPanel.Children.Add(_listBox);

        var buttons = ButtonRow();
        var open = PrimaryButton("開く");
        open.Click += (_, _) => OpenSelectedDetail();
        var updatePassword = SecondaryButton("PW更新");
        updatePassword.Click += (_, _) => ShowMasterPasswordUpdate(string.Empty);
        var lockButton = SecondaryButton("ロック");
        lockButton.Click += (_, _) => LockNow();
        buttons.Children.Add(open);
        buttons.Children.Add(updatePassword);
        buttons.Children.Add(lockButton);
        RootPanel.Children.Add(buttons);

        if (!LoadList(string.Empty)) return;
        _searchBox?.Focus();
    }

    private bool LoadList(string query)
    {
        if (_listBox == null) return false;
        IReadOnlyList<CredentialSummary> all;
        try
        {
            all = _credentialRepository.GetSummaries();
        }
        catch (Exception ex)
        {
            ShowAccessBlocked("資格情報データを読み込めません。起動後に削除・破損・改ざんされた可能性があります。バックアップから復元してください。詳細: " + ex.Message);
            return false;
        }

        var filtered = string.IsNullOrWhiteSpace(query)
            ? all
            : all.Where(x => Contains(x.ServiceName, query) || Contains(x.Website, query) || Contains(x.Username, query) || Contains(x.Memo, query)).ToList();

        _listBox.Items.Clear();
        if (filtered.Count == 0)
        {
            _listBox.Items.Add(new ListBoxItem
            {
                Content = new TextBlock
                {
                    Text = "登録データがありません。右上の［追加］から登録してください。",
                    Foreground = Brushes.DimGray,
                    TextWrapping = TextWrapping.Wrap,
                    Margin = new Thickness(8)
                },
                IsEnabled = false
            });
            return true;
        }

        foreach (var item in filtered)
        {
            var panel = new StackPanel { Margin = new Thickness(8, 6, 8, 6) };
            panel.Children.Add(new TextBlock
            {
                Text = string.IsNullOrWhiteSpace(item.ServiceName) ? "（名称未設定）" : item.ServiceName,
                FontSize = 15,
                FontWeight = FontWeights.Bold,
                Foreground = new SolidColorBrush(Color.FromRgb(17, 24, 39)),
                TextTrimming = TextTrimming.CharacterEllipsis
            });
            panel.Children.Add(new TextBlock
            {
                Text = string.IsNullOrWhiteSpace(item.Website) ? "（URL未入力）" : item.Website,
                FontSize = 12,
                Foreground = Brushes.DimGray,
                TextTrimming = TextTrimming.CharacterEllipsis
            });
            panel.Children.Add(new TextBlock
            {
                Text = "更新日：" + ToLocalText(item.UpdatedAt),
                FontSize = 11,
                Foreground = Brushes.Gray,
                TextTrimming = TextTrimming.CharacterEllipsis
            });

            _listBox.Items.Add(new ListBoxItem
            {
                Content = panel,
                Tag = item.Id,
                Padding = new Thickness(0),
                Margin = new Thickness(0, 0, 0, 3)
            });
        }
        return true;
    }

    private static bool Contains(string value, string query) => value.Contains(query, StringComparison.OrdinalIgnoreCase);

    private void OpenSelectedDetail()
    {
        if (_listBox?.SelectedItem is ListBoxItem { Tag: long id })
        {
            try
            {
                ShowDetail(_credentialRepository.GetById(id));
            }
            catch (Exception ex)
            {
                ShowAccessBlocked("資格情報データを開けません。起動後に削除・破損・改ざんされた可能性があります。バックアップから復元してください。詳細: " + ex.Message);
            }
            return;
        }
        SetStatus("一覧から対象を選択してください。", 4, StatusKind.Error);
    }

    private void ShowDetail(CredentialItem item)
    {
        if (!_isUnlocked)
        {
            ShowUnlock();
            return;
        }

        _currentDetail = item;
        _usernameRevealed = false;
        _passwordRevealed = false;
        ResetRoot("詳細表示");

        AddReadonlyRow("サービス名", item.ServiceName, null);
        AddReadonlyRow("ウェブサイト", item.Website, () => CopyValue(item.Website, "ウェブサイトをコピーしました。", StatusKind.Success));
        AddSecretRow("ユーザー名", item.Username, isUsername: true);
        AddSecretRow("パスワード", item.Password, isUsername: false);
        AddReadonlyRow("メモ", item.Memo, null, maxHeight: 58);
        AddReadonlyRow("更新日", ToLocalText(item.UpdatedAt), null);

        var buttons = ButtonRow();
        var edit = PrimaryButton("編集");
        edit.Click += (_, _) => ShowEdit(item);
        var delete = DangerButton("削除");
        delete.Click += (_, _) => RequestOrExecuteDelete(item.Id);
        var back = SecondaryButton("戻る");
        back.Click += (_, _) => ShowSearch();
        buttons.Children.Add(edit);
        buttons.Children.Add(delete);
        buttons.Children.Add(back);
        RootPanel.Children.Add(buttons);

        SetStatus("ユーザー名・パスワードは初期非表示です。表示・コピー内容は30秒で自動保護します。", 0, StatusKind.Info);
    }

    private void AddSecretRow(string label, string value, bool isUsername)
    {
        var row = new Grid { Margin = new Thickness(0, 5, 0, 5) };
        row.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(96) });
        row.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        row.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        row.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        row.Children.Add(LabelText(label));

        var text = ValueText(SecretMask);
        Grid.SetColumn(text, 1);
        row.Children.Add(text);
        if (isUsername) _detailUsernameText = text;
        else _detailPasswordText = text;

        var reveal = SmallButton("表示");
        if (isUsername) _detailUsernameRevealButton = reveal;
        else _detailPasswordRevealButton = reveal;
        reveal.Click += (_, _) =>
        {
            if (!_isUnlocked)
            {
                ShowUnlock();
                return;
            }
            if (isUsername) ToggleRevealUsername(reveal);
            else ToggleRevealPassword(reveal);
        };
        Grid.SetColumn(reveal, 2);
        row.Children.Add(reveal);

        var copy = SmallButton("コピー");
        copy.Click += (_, _) =>
        {
            if (!_isUnlocked)
            {
                ShowUnlock();
                return;
            }
            CopyValue(value, isUsername ? "ユーザー名をコピーしました。" : "パスワードをコピーしました。30秒後に削除します。", StatusKind.Success);
        };
        Grid.SetColumn(copy, 3);
        row.Children.Add(copy);
        RootPanel.Children.Add(row);
    }

    private void ToggleRevealUsername(Button button)
    {
        if (_currentDetail == null || _detailUsernameText == null) return;
        _usernameRevealed = !_usernameRevealed;
        _detailUsernameText.Text = _usernameRevealed ? _currentDetail.Username : SecretMask;
        button.Content = _usernameRevealed ? "隠す" : "表示";
        RestartRevealTimerIfNeeded();
    }

    private void ToggleRevealPassword(Button button)
    {
        if (_currentDetail == null || _detailPasswordText == null) return;
        _passwordRevealed = !_passwordRevealed;
        _detailPasswordText.Text = _passwordRevealed ? _currentDetail.Password : SecretMask;
        button.Content = _passwordRevealed ? "隠す" : "表示";
        RestartRevealTimerIfNeeded();
    }

    private void RestartRevealTimerIfNeeded()
    {
        _revealTimer.Stop();
        if (_usernameRevealed || _passwordRevealed)
        {
            _revealTimer.Interval = TimeSpan.FromSeconds(_settings.PasswordRevealSeconds);
            _revealTimer.Start();
        }
    }

    private void HideRevealedSecrets()
    {
        _revealTimer.Stop();
        _usernameRevealed = false;
        _passwordRevealed = false;
        if (_detailUsernameText != null) _detailUsernameText.Text = SecretMask;
        if (_detailPasswordText != null) _detailPasswordText.Text = SecretMask;
        if (_detailUsernameRevealButton != null) _detailUsernameRevealButton.Content = "表示";
        if (_detailPasswordRevealButton != null) _detailPasswordRevealButton.Content = "表示";
    }

    private void ShowEdit(CredentialItem? sourceItem)
    {
        if (!_isUnlocked)
        {
            ShowUnlock();
            return;
        }

        var isNew = sourceItem == null;
        var item = sourceItem == null
            ? new CredentialItem()
            : new CredentialItem
            {
                Id = sourceItem.Id,
                ServiceName = sourceItem.ServiceName,
                Website = sourceItem.Website,
                Username = sourceItem.Username,
                Password = sourceItem.Password,
                Memo = sourceItem.Memo,
                CreatedAt = sourceItem.CreatedAt,
                UpdatedAt = sourceItem.UpdatedAt
            };

        ResetRoot(isNew ? "追加" : "編集");

        var service = AddTextBox("サービス名", item.ServiceName, 34);
        var website = AddTextBox("ウェブサイト", item.Website, 34);
        var username = AddTextBox("ユーザー名", item.Username, 34);
        var password = AddPasswordInput("パスワード", item.Password, null);
        var memo = AddMultilineTextBox("メモ", item.Memo);
        if (!isNew && item.UpdatedAt != default) AddHint("更新日：" + ToLocalText(item.UpdatedAt));

        var buttons = ButtonRow();
        var save = PrimaryButton("保存");
        save.Click += (_, _) =>
        {
            if (string.IsNullOrWhiteSpace(service.Text))
            {
                SetStatus("サービス名を入力してください。", 5, StatusKind.Error);
                return;
            }
            if (string.IsNullOrEmpty(password.Password))
            {
                SetStatus("パスワードを入力してください。", 5, StatusKind.Error);
                return;
            }

            item.ServiceName = service.Text.Trim();
            item.Website = website.Text.Trim();
            item.Username = username.Text.Trim();
            item.Password = password.Password;
            item.Memo = memo.Text.Trim();
            try
            {
                _credentialRepository.Upsert(item);
            }
            catch (Exception ex)
            {
                ShowAccessBlocked("資格情報データへ保存できません。起動後に削除・破損・改ざんされた可能性があります。バックアップから復元してください。詳細: " + ex.Message);
                return;
            }
            password.Password = string.Empty;
            ShowSearch();
            SetStatus(isNew ? "追加しました。" : "保存しました。", 5, StatusKind.Success);
        };
        buttons.Children.Add(save);

        if (!isNew)
        {
            var delete = DangerButton("削除");
            delete.Click += (_, _) => RequestOrExecuteDelete(item.Id);
            buttons.Children.Add(delete);
        }

        var cancel = SecondaryButton("キャンセル");
        cancel.Click += (_, _) =>
        {
            if (isNew) ShowSearch();
            else ShowDetail(sourceItem!);
        };
        buttons.Children.Add(cancel);
        RootPanel.Children.Add(buttons);
    }

    private void RequestOrExecuteDelete(long id)
    {
        if (!_isUnlocked)
        {
            ShowUnlock();
            return;
        }

        if (_pendingDeleteId == id && DateTime.UtcNow <= _pendingDeleteExpiresUtc)
        {
            try
            {
                _credentialRepository.Delete(id);
            }
            catch (Exception ex)
            {
                ShowAccessBlocked("資格情報データを削除できません。起動後に削除・破損・改ざんされた可能性があります。バックアップから復元してください。詳細: " + ex.Message);
                return;
            }
            _pendingDeleteId = null;
            _pendingDeleteExpiresUtc = default;
            ShowSearch();
            SetStatus("削除しました。", 5, StatusKind.Success);
            return;
        }

        _pendingDeleteId = id;
        _pendingDeleteExpiresUtc = DateTime.UtcNow.AddSeconds(6);
        SetStatus("削除する場合は、6秒以内にもう一度［削除］を押してください。", 6, StatusKind.Warning);
    }

    private void ShowExport()
    {
        if (!_isUnlocked)
        {
            ShowUnlock();
            return;
        }

        ResetRoot("エクスポート");
        AddDescription("出力前にマスターパスワードを再入力してください。");
        AddWarning("バックアップは settings.json と暗号化済みDBをまとめたポータブル形式です。CSV出力はユーザー名・パスワードを平文で含みます。移行や確認が終わったら、CSVは速やかに完全削除してください。");
        var master = AddPasswordInput("マスターパスワード", string.Empty, MasterPasswordMaxLength);

        var buttons1 = ButtonRow();
        var backup = PrimaryButton("バックアップ作成");
        backup.Width = 138;
        backup.Click += (_, _) => ExecuteExport(master.Password, csv: false);
        var csv = DangerButton("CSV出力");
        csv.Width = 96;
        csv.Click += (_, _) => ExecuteExport(master.Password, csv: true);
        buttons1.Children.Add(backup);
        buttons1.Children.Add(csv);
        RootPanel.Children.Add(buttons1);

        var buttons2 = ButtonRow();
        var back = SecondaryButton("戻る");
        back.Click += (_, _) => ShowSearch();
        buttons2.Children.Add(back);
        RootPanel.Children.Add(buttons2);
    }

    private void ExecuteExport(string masterPassword, bool csv)
    {
        var master = NormalizeMasterPassword(masterPassword);
        if (!VerifyMasterPasswordForSensitiveAction(master, "マスターパスワードが違います。"))
        {
            return;
        }

        var dialog = new SaveFileDialog
        {
            Title = csv ? "CSVエクスポート" : "パス金庫バックアップ作成",
            FileName = csv
                ? "passkinko_export_" + DateTime.Now.ToString("yyyyMMdd_HHmmss", CultureInfo.InvariantCulture) + ".csv"
                : "passkinko_backup_" + DateTime.Now.ToString("yyyyMMdd_HHmmss", CultureInfo.InvariantCulture) + ".pkbk",
            Filter = csv ? "CSVファイル (*.csv)|*.csv" : "パス金庫バックアップ (*.pkbk)|*.pkbk"
        };

        if (dialog.ShowDialog(this) != true) return;

        try
        {
            if (csv)
            {
                _credentialRepository.ExportCsv(dialog.FileName);
                SetStatus("CSVを出力しました。平文ファイルのため、利用後は完全削除してください: " + dialog.FileName, 10, StatusKind.Warning);
            }
            else
            {
                _credentialRepository.ExportPortableBackup(dialog.FileName, _settings);
                SetStatus("バックアップを作成しました: " + dialog.FileName, 8, StatusKind.Success);
            }
        }
        catch (Exception ex)
        {
            SetStatus("エクスポートに失敗しました: " + ex.Message, 8, StatusKind.Error);
        }
    }

    private void ShowMasterPasswordUpdate(string message)
    {
        _isUnlocked = _activeKeys != null;
        MarkActivity();
        ResetRoot("マスターパスワード更新");
        if (!string.IsNullOrWhiteSpace(message)) AddWarning(message);
        AddDescription("マスターパスワードは最大1年ごとに更新します。");
        var current = AddPasswordInput("現在のマスターパスワード", string.Empty, MasterPasswordMaxLength);
        var next = AddPasswordInput("新しいマスターパスワード", string.Empty, MasterPasswordMaxLength);
        var confirm = AddPasswordInput("新しいマスターパスワード確認", string.Empty, MasterPasswordMaxLength);
        AddHint("入力仕様：8〜64文字 / 空白のみ不可 / 推奨：長いパスフレーズまたは英字・数字・記号の組み合わせ");

        var buttons = ButtonRow();
        var save = PrimaryButton("更新");
        save.Click += (_, _) =>
        {
            var currentPw = NormalizeMasterPassword(current.Password);
            var nextPw = NormalizeMasterPassword(next.Password);
            var confirmPw = NormalizeMasterPassword(confirm.Password);

            if (!VerifyMasterPasswordForSensitiveAction(currentPw, "現在のマスターパスワードが違います。"))
            {
                return;
            }
            var validation = ValidateMasterPassword(nextPw);
            if (validation != null)
            {
                SetStatus(validation, 5, StatusKind.Error);
                return;
            }
            if (nextPw != confirmPw)
            {
                SetStatus("新しいマスターパスワードと確認入力が一致しません。", 5, StatusKind.Error);
                return;
            }

            try
            {
                UpdateMasterPasswordAtomically(nextPw);
            }
            catch (Exception ex)
            {
                ShowAccessBlocked("マスターパスワード更新に失敗しました。安全のため処理を停止します。既存バックアップがある場合は自動復旧を試みています。詳細: " + ex.Message);
                return;
            }

            current.Password = string.Empty;
            next.Password = string.Empty;
            confirm.Password = string.Empty;
            _isUnlocked = true;
            MarkActivity();
            ShowSearch();
            SetStatus("マスターパスワードを更新しました。", 5, StatusKind.Success);
        };
        buttons.Children.Add(save);

        if (!_masterPasswordService.IsPasswordExpired(_settings))
        {
            var cancel = SecondaryButton("キャンセル");
            cancel.Click += (_, _) =>
            {
                _isUnlocked = true;
                ShowSearch();
            };
            buttons.Children.Add(cancel);
        }
        RootPanel.Children.Add(buttons);
    }

    private void UpdateMasterPasswordAtomically(string newMasterPassword)
    {
        var items = _credentialRepository.GetAll().ToList();

        var newSettings = _masterPasswordService.CreateInitialSettings(newMasterPassword);
        newSettings.AutoLockSeconds = _settings.AutoLockSeconds;
        newSettings.PasswordRevealSeconds = _settings.PasswordRevealSeconds;
        newSettings.ClipboardClearSeconds = _settings.ClipboardClearSeconds;
        newSettings.WindowAnchor = _settings.WindowAnchor;

        var newKeys = _masterPasswordService.DeriveKeys(newMasterPassword, newSettings);
        _operationalStateService.ProtectInto(newSettings);

        var tempDb = AppPaths.DatabasePath + ".v10new";
        var tempSettings = AppPaths.SettingsPath + ".v10new";
        var dbBackup = AppPaths.DatabasePath + ".v10bak";
        var settingsBackup = AppPaths.SettingsPath + ".v10bak";

        try
        {
            DeleteIfExists(tempDb);
            DeleteIfExists(tempSettings);
            DeleteIfExists(dbBackup);
            DeleteIfExists(settingsBackup);

            var newRepo = new CredentialRepository(_crypto, () => newKeys);
            newRepo.WriteAllToPath(items, tempDb, newKeys);
            newRepo.ValidateVaultAtPath(tempDb, newKeys);
            _settingsRepository.SaveToPath(newSettings, tempSettings, newKeys);

            if (!_masterPasswordService.VerifySettingsSignature(newSettings, newKeys))
            {
                throw new InvalidDataException("新settingsの署名検証に失敗しました。");
            }

            ReplaceFile(tempDb, AppPaths.DatabasePath, dbBackup);
            try
            {
                ReplaceFile(tempSettings, AppPaths.SettingsPath, settingsBackup);
            }
            catch
            {
                RestoreFile(dbBackup, AppPaths.DatabasePath);
                throw;
            }

            _activeKeys?.Dispose();
            _settings = newSettings;
            _activeKeys = newKeys;
            _credentialRepository = new CredentialRepository(_crypto, GetActiveKeys);
            _operationalStateRecoveryRequired = false;
            _operationalStateRecoveryMessage = string.Empty;
            _operationalStateRecoveryStopwatch = null;
        }
        catch
        {
            RestoreFile(dbBackup, AppPaths.DatabasePath);
            RestoreFile(settingsBackup, AppPaths.SettingsPath);
            throw;
        }
        finally
        {
            DeleteIfExists(tempDb);
            DeleteIfExists(tempSettings);
        }
    }

    private static void ReplaceFile(string sourceTemp, string target, string backup)
    {
        if (!File.Exists(sourceTemp)) throw new FileNotFoundException("置換元ファイルがありません。", sourceTemp);
        if (File.Exists(target))
        {
            DeleteIfExists(backup);
            File.Replace(sourceTemp, target, backup, true);
        }
        else
        {
            File.Move(sourceTemp, target);
        }
    }

    private static void RestoreFile(string backup, string target)
    {
        if (!File.Exists(backup)) return;
        File.Copy(backup, target, true);
    }

    private static void DeleteIfExists(string path)
    {
        if (File.Exists(path)) File.Delete(path);
    }

    private bool VerifyMasterPasswordForSensitiveAction(string masterPassword, string failureMessage)
    {
        if (_settings.LockoutUntilUtc > DateTime.UtcNow)
        {
            SetStatus("一時ロック中です。解除予定：" + ToLocalText(_settings.LockoutUntilUtc), 8, StatusKind.Error);
            return false;
        }

        if (_masterPasswordService.Verify(masterPassword, _settings))
        {
            _settings.FailedUnlockCount = 0;
            _settings.LockoutUntilUtc = default;
            SaveSettings(_activeKeys);
            return true;
        }

        _settings.FailedUnlockCount++;
        if (_settings.FailedUnlockCount >= 10)
        {
            _settings.LockoutUntilUtc = DateTime.UtcNow.AddMinutes(30);
            _settings.FailedUnlockCount = 0;
            SaveSettings(_activeKeys);
            ClearSensitiveState();
            _activeKeys?.Dispose();
            _activeKeys = null;
            _isUnlocked = false;
            ShowUnlock();
            SetStatus("マスターパスワードを10回間違えたため、30分間ロックします。", 8, StatusKind.Error);
            return false;
        }

        SaveSettings(_activeKeys);
        SetStatus(failureMessage + " 残り " + (10 - _settings.FailedUnlockCount) + " 回です。", 5, StatusKind.Error);
        return false;
    }

    private void CopyValue(string value, string message, StatusKind kind = StatusKind.Info)
    {
        if (string.IsNullOrEmpty(value))
        {
            SetStatus("コピー対象がありません。", 5, StatusKind.Error);
            return;
        }

        _clipboard.Copy(value, _settings.ClipboardClearSeconds);
        SetStatus(message, 5, kind);
    }


    private void RestorePortableBackupFromDialog()
    {
        var dialog = new OpenFileDialog
        {
            Title = "パス金庫バックアップ復元",
            Filter = "パス金庫バックアップ (*.pkbk)|*.pkbk"
        };
        if (dialog.ShowDialog(this) != true) return;

        try
        {
            BackupCurrentDataToQuarantine("restore_before");
            _credentialRepository.RestorePortableBackup(dialog.FileName);
            _settings = _settingsRepository.Load();
            _operationalStateRecoveryRequired = true;
            _operationalStateRecoveryMessage = "バックアップを復元しました。運用状態はこのPCで再構築が必要です。";
            _operationalStateRecoveryStopwatch = Stopwatch.StartNew();
            _activeKeys?.Dispose();
            _activeKeys = null;
            _isUnlocked = false;
            ShowUnlock();
            SetStatus("バックアップを復元しました。待機後、マスターパスワードで解除してください。", 8, StatusKind.Success);
        }
        catch (Exception ex)
        {
            SetStatus("バックアップ復元に失敗しました: " + ex.Message, 8, StatusKind.Error);
        }
    }

    private void ShowStartOverConfirm()
    {
        ResetRoot("新規開始確認");
        AddWarning("既存データを削除せず退避フォルダへ移動し、パス金庫を初期状態から開始します。マスターパスワードを忘れた場合や旧形式データで起動できない場合の救済操作です。退避データは復号できることを保証しません。");
        var buttons = ButtonRow();
        var start = DangerButton("退避して新規開始");
        start.Width = 150;
        start.Click += (_, _) => StartOverWithQuarantine();
        var back = SecondaryButton("戻る");
        back.Click += (_, _) => RouteStartup();
        buttons.Children.Add(start);
        buttons.Children.Add(back);
        RootPanel.Children.Add(buttons);
    }

    private void StartOverWithQuarantine()
    {
        try
        {
            BackupCurrentDataToQuarantine("start_over");
            DeleteIfExists(AppPaths.DatabasePath);
            DeleteIfExists(AppPaths.SettingsPath);
            _activeKeys?.Dispose();
            _activeKeys = null;
            _settings = new AppSettings();
            _operationalStateRecoveryRequired = false;
            _operationalStateRecoveryMessage = string.Empty;
            _operationalStateRecoveryStopwatch = null;
            _credentialRepository = new CredentialRepository(_crypto, GetActiveKeys);
            ShowFirstLaunch();
            SetStatus("既存データを退避し、新規開始します。", 8, StatusKind.Warning);
        }
        catch (Exception ex)
        {
            SetStatus("新規開始に失敗しました: " + ex.Message, 8, StatusKind.Error);
        }
    }

    private static void BackupCurrentDataToQuarantine(string reason)
    {
        AppPaths.EnsureDirectories();
        if (!File.Exists(AppPaths.DatabasePath) && !File.Exists(AppPaths.SettingsPath)) return;
        var dir = Path.Combine(AppPaths.AppDataDirectory, "quarantine_" + reason + "_" + DateTime.Now.ToString("yyyyMMdd_HHmmss", CultureInfo.InvariantCulture));
        Directory.CreateDirectory(dir);
        if (File.Exists(AppPaths.DatabasePath)) File.Copy(AppPaths.DatabasePath, Path.Combine(dir, Path.GetFileName(AppPaths.DatabasePath)), true);
        if (File.Exists(AppPaths.SettingsPath)) File.Copy(AppPaths.SettingsPath, Path.Combine(dir, Path.GetFileName(AppPaths.SettingsPath)), true);
    }

    public void ShowFromTray()
    {
        if (_settings.IsInitialized)
        {
            LockForHiddenState();
        }
        else
        {
            ShowFirstLaunch();
        }

        WindowPositionService.MoveToBottomLeft(this);
        Show();
        WindowState = WindowState.Normal;
        Activate();
    }

    private void LockNow()
    {
        if (_settings.IsInitialized)
        {
            LockForHiddenState();
            WindowPositionService.MoveToBottomLeft(this);
            Show();
            WindowState = WindowState.Normal;
            Activate();
        }
    }

    private void LockForHiddenState()
    {
        _clipboard.ClearIfUnchanged();
        ClearSensitiveState();
        _activeKeys?.Dispose();
        _activeKeys = null;
        _isUnlocked = false;
        if (_settings.IsInitialized)
        {
            if (_settings.InitializationRequired) ShowAccessBlocked(_settings.SecurityMessage);
            else ShowUnlock();
        }
        else
        {
            ShowFirstLaunch();
        }
    }

    private void ClearSensitiveState()
    {
        HideRevealedSecrets();
        _currentDetail = null;
        if (_unlockPasswordInput != null) _unlockPasswordInput.Password = string.Empty;
        _unlockPasswordInput = null;
        if (_searchBox != null) _searchBox.Text = string.Empty;
        _searchBox = null;
        if (_listBox != null) _listBox.Items.Clear();
        _listBox = null;
        _detailUsernameText = null;
        _detailPasswordText = null;
        _detailUsernameRevealButton = null;
        _detailPasswordRevealButton = null;
        _pendingDeleteId = null;
        _pendingDeleteExpiresUtc = default;
    }

    private static string NormalizeMasterPassword(string value) => value.Trim();

    private static string? ValidateMasterPassword(string value)
    {
        if (string.IsNullOrWhiteSpace(value)) return "マスターパスワードを入力してください。";
        if (value.Length < MasterPasswordService.MinLength) return "マスターパスワードは8文字以上で入力してください。";
        if (value.Length > MasterPasswordMaxLength) return "マスターパスワードは64文字以内で入力してください。";
        return null;
    }

    private void SetStatus(string message, int seconds = 5, StatusKind kind = StatusKind.Info)
    {
        StatusTextBlock.Text = message;
        StatusTextBlock.Foreground = kind switch
        {
            StatusKind.Success => new SolidColorBrush(Color.FromRgb(22, 101, 52)),
            StatusKind.Warning => new SolidColorBrush(Color.FromRgb(180, 83, 9)),
            StatusKind.Error => ErrorBrush(),
            _ => new SolidColorBrush(Color.FromRgb(37, 99, 235))
        };
        _statusTimer.Stop();
        if (!string.IsNullOrEmpty(message) && seconds > 0)
        {
            _statusTimer.Interval = TimeSpan.FromSeconds(seconds);
            _statusTimer.Start();
        }
    }

    private void AddDescription(string text)
    {
        RootPanel.Children.Add(new TextBlock
        {
            Text = text,
            TextWrapping = TextWrapping.Wrap,
            Foreground = new SolidColorBrush(Color.FromRgb(55, 65, 81)),
            FontSize = 13,
            Margin = new Thickness(0, 0, 0, 10)
        });
    }

    private void AddHint(string text)
    {
        RootPanel.Children.Add(new TextBlock
        {
            Text = text,
            TextWrapping = TextWrapping.Wrap,
            Foreground = Brushes.DimGray,
            FontSize = 12,
            Margin = new Thickness(0, 0, 0, 6)
        });
    }

    private void AddVersionStamp()
    {
        RootPanel.Children.Add(new TextBlock
        {
            Text = ProgramVersion,
            HorizontalAlignment = HorizontalAlignment.Right,
            Foreground = Brushes.Gray,
            FontSize = 10,
            Margin = new Thickness(0, 6, 0, 0)
        });
    }

    private void AddWarning(string text)
    {
        RootPanel.Children.Add(new Border
        {
            BorderBrush = ErrorBrush(),
            Background = new SolidColorBrush(Color.FromRgb(254, 242, 242)),
            BorderThickness = new Thickness(1),
            CornerRadius = new CornerRadius(6),
            Padding = new Thickness(10),
            Margin = new Thickness(0, 0, 0, 12),
            Child = new TextBlock
            {
                Text = text,
                TextWrapping = TextWrapping.Wrap,
                Foreground = ErrorBrush(),
                FontSize = 13,
                LineHeight = 21
            }
        });
    }

    private PasswordInput AddPasswordInput(string label, string initialValue, int? maxLength)
    {
        RootPanel.Children.Add(new TextBlock
        {
            Text = label,
            FontSize = 13,
            FontWeight = FontWeights.Bold,
            Foreground = new SolidColorBrush(Color.FromRgb(17, 24, 39)),
            Margin = new Thickness(0, 3, 0, 3)
        });

        var grid = new Grid { Margin = new Thickness(0, 0, 0, 8) };
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

        var hidden = new PasswordBox
        {
            Height = 34,
            FontSize = 14,
            Padding = new Thickness(8, 5, 8, 5),
            Password = initialValue
        };
        var visible = new TextBox
        {
            Height = 34,
            FontSize = 14,
            Padding = new Thickness(8, 5, 8, 5),
            Text = initialValue,
            Visibility = Visibility.Collapsed
        };
        if (maxLength.HasValue)
        {
            hidden.MaxLength = maxLength.Value;
            visible.MaxLength = maxLength.Value;
        }

        Grid.SetColumn(hidden, 0);
        Grid.SetColumn(visible, 0);
        grid.Children.Add(hidden);
        grid.Children.Add(visible);

        var toggle = SmallButton("表示");
        toggle.Margin = new Thickness(8, 0, 0, 0);
        Grid.SetColumn(toggle, 1);
        grid.Children.Add(toggle);
        RootPanel.Children.Add(grid);

        return new PasswordInput(hidden, visible, toggle);
    }

    private TextBox AddTextBox(string label, string value, int height)
    {
        RootPanel.Children.Add(new TextBlock
        {
            Text = label,
            FontSize = 13,
            FontWeight = FontWeights.Bold,
            Margin = new Thickness(0, 1, 0, 2)
        });
        var tb = new TextBox
        {
            Text = value,
            Height = height,
            FontSize = 14,
            Padding = new Thickness(8, 5, 8, 5),
            Margin = new Thickness(0, 0, 0, 5)
        };
        RootPanel.Children.Add(tb);
        return tb;
    }

    private TextBox AddMultilineTextBox(string label, string value)
    {
        RootPanel.Children.Add(new TextBlock
        {
            Text = label,
            FontSize = 13,
            FontWeight = FontWeights.Bold,
            Margin = new Thickness(0, 1, 0, 2)
        });
        var tb = new TextBox
        {
            Text = value,
            Height = 58,
            FontSize = 14,
            Padding = new Thickness(8, 5, 8, 5),
            AcceptsReturn = true,
            TextWrapping = TextWrapping.Wrap,
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
            Margin = new Thickness(0, 0, 0, 5)
        };
        RootPanel.Children.Add(tb);
        return tb;
    }

    private void AddReadonlyRow(string label, string value, Action? copyAction, double? maxHeight = null)
    {
        var row = new Grid { Margin = new Thickness(0, 4, 0, 5) };
        row.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(96) });
        row.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        row.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        row.Children.Add(LabelText(label));

        var valueText = ValueText(string.IsNullOrEmpty(value) ? "（未入力）" : value);
        if (maxHeight.HasValue) valueText.MaxHeight = maxHeight.Value;
        Grid.SetColumn(valueText, 1);
        row.Children.Add(valueText);

        if (copyAction != null)
        {
            var copy = SmallButton("コピー");
            copy.Click += (_, _) => copyAction();
            Grid.SetColumn(copy, 2);
            row.Children.Add(copy);
        }
        RootPanel.Children.Add(row);
    }

    private static TextBlock LabelText(string text) => new()
    {
        Text = text,
        FontSize = 13,
        FontWeight = FontWeights.Bold,
        Foreground = new SolidColorBrush(Color.FromRgb(17, 24, 39)),
        VerticalAlignment = VerticalAlignment.Center
    };

    private static TextBlock ValueText(string text) => new()
    {
        Text = text,
        FontSize = 13,
        TextWrapping = TextWrapping.Wrap,
        VerticalAlignment = VerticalAlignment.Center,
        Background = new SolidColorBrush(Color.FromRgb(249, 250, 251)),
        Padding = new Thickness(8, 6, 8, 6),
        MinHeight = 34
    };

    private static StackPanel ButtonRow() => new()
    {
        Orientation = Orientation.Horizontal,
        HorizontalAlignment = HorizontalAlignment.Left,
        Margin = new Thickness(0, 10, 0, 0)
    };

    private static Button PrimaryButton(string text) => new()
    {
        Content = text,
        Width = 96,
        Height = 32,
        Margin = new Thickness(0, 0, 8, 0),
        Background = new SolidColorBrush(Color.FromRgb(11, 99, 216)),
        Foreground = Brushes.White,
        BorderBrush = new SolidColorBrush(Color.FromRgb(11, 99, 216)),
        FontSize = 13,
        FontWeight = FontWeights.Bold
    };

    private static Button SecondaryButton(string text) => new()
    {
        Content = text,
        Width = 96,
        Height = 32,
        Margin = new Thickness(0, 0, 8, 0),
        FontSize = 13
    };

    private static Button DangerButton(string text) => new()
    {
        Content = text,
        Width = 96,
        Height = 32,
        Margin = new Thickness(0, 0, 8, 0),
        Background = new SolidColorBrush(Color.FromRgb(220, 38, 38)),
        Foreground = Brushes.White,
        BorderBrush = new SolidColorBrush(Color.FromRgb(220, 38, 38)),
        FontSize = 13,
        FontWeight = FontWeights.Bold
    };

    private static Button SmallButton(string text) => new()
    {
        Content = text,
        Width = 56,
        Height = 30,
        Margin = new Thickness(6, 0, 0, 0),
        FontSize = 12
    };

    private static SolidColorBrush ErrorBrush() => new(Color.FromRgb(220, 38, 38));

    private TimeSpan GetOperationalRecoveryRemaining()
    {
        if (!_operationalStateRecoveryRequired || _operationalStateRecoveryStopwatch == null) return TimeSpan.Zero;
        var remaining = _operationalStateRecoveryDelay - _operationalStateRecoveryStopwatch.Elapsed;
        return remaining > TimeSpan.Zero ? remaining : TimeSpan.Zero;
    }

    private static string FormatRemaining(TimeSpan remaining)
    {
        if (remaining <= TimeSpan.Zero) return "0秒";
        return $"{Math.Ceiling(remaining.TotalMinutes):0}分";
    }

    private static string ToLocalText(DateTime utc)
    {
        if (utc == default) return "未設定";
        return utc.ToLocalTime().ToString("yyyy/MM/dd HH:mm", CultureInfo.InvariantCulture);
    }

    private static string ToLocalDate(DateTime utc)
    {
        if (utc == default) return "未設定";
        return utc.ToLocalTime().ToString("yyyy/MM/dd", CultureInfo.InvariantCulture);
    }

    private sealed class PasswordInput
    {
        private readonly PasswordBox _hidden;
        private readonly TextBox _visible;
        private readonly Button _toggle;
        private bool _isVisible;

        public PasswordInput(PasswordBox hidden, TextBox visible, Button toggle)
        {
            _hidden = hidden;
            _visible = visible;
            _toggle = toggle;
            _toggle.Click += (_, _) => Toggle();
        }

        public string Password
        {
            get => _isVisible ? _visible.Text : _hidden.Password;
            set
            {
                _hidden.Password = value;
                _visible.Text = value;
            }
        }

        public event KeyEventHandler KeyDown
        {
            add
            {
                _hidden.KeyDown += value;
                _visible.KeyDown += value;
            }
            remove
            {
                _hidden.KeyDown -= value;
                _visible.KeyDown -= value;
            }
        }

        public void Focus()
        {
            if (_isVisible) _visible.Focus();
            else _hidden.Focus();
        }

        private void Toggle()
        {
            if (_isVisible)
            {
                _hidden.Password = _visible.Text;
                _visible.Visibility = Visibility.Collapsed;
                _hidden.Visibility = Visibility.Visible;
                _toggle.Content = "表示";
                _hidden.Focus();
            }
            else
            {
                _visible.Text = _hidden.Password;
                _hidden.Visibility = Visibility.Collapsed;
                _visible.Visibility = Visibility.Visible;
                _toggle.Content = "隠す";
                _visible.Focus();
                _visible.CaretIndex = _visible.Text.Length;
            }
            _isVisible = !_isVisible;
        }
    }
}
