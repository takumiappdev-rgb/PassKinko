using System;
using System.Windows;
using System.Windows.Threading;

namespace PassKinko.App.Services;

public sealed class ClipboardService
{
    private readonly DispatcherTimer _timer;
    private string? _lastCopied;

    public ClipboardService()
    {
        _timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(30) };
        _timer.Tick += (_, _) => ClearIfUnchanged();
    }

    public void Copy(string value, int clearAfterSeconds)
    {
        if (string.IsNullOrEmpty(value)) return;

        var data = new DataObject();
        data.SetData(DataFormats.UnicodeText, value);
        data.SetData(DataFormats.Text, value);

        // Windows 10/11 のクリップボード履歴・クラウド同期に載せないための既知フォーマット。
        // OSや環境により完全保証ではないため、30秒後クリアも併用する。
        data.SetData("ExcludeClipboardContentFromMonitorProcessing", true);
        data.SetData("CanIncludeInClipboardHistory", false);
        data.SetData("CanUploadToCloudClipboard", false);

        Clipboard.SetDataObject(data, true);
        _lastCopied = value;
        _timer.Stop();
        _timer.Interval = TimeSpan.FromSeconds(clearAfterSeconds);
        _timer.Start();
    }

    public void ClearIfUnchanged()
    {
        _timer.Stop();
        try
        {
            if (_lastCopied != null && Clipboard.ContainsText() && Clipboard.GetText() == _lastCopied)
            {
                Clipboard.Clear();
            }
        }
        catch
        {
            // Clipboard may be locked by another process. Do not crash the app.
        }
        finally
        {
            _lastCopied = null;
        }
    }
}
