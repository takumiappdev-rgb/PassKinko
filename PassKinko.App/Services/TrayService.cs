using System;
using System.Drawing;
using System.IO;
using System.Windows;
using Forms = System.Windows.Forms;

namespace PassKinko.App.Services;

public sealed class TrayService : IDisposable
{
    private readonly Forms.NotifyIcon _notifyIcon;
    private readonly Window _window;
    private readonly Action _lockAction;

    public TrayService(Window window, Action lockAction)
    {
        _window = window;
        _lockAction = lockAction;

        var iconPath = Path.Combine(AppContext.BaseDirectory, "Assets", "app.ico");
        _notifyIcon = new Forms.NotifyIcon
        {
            Text = "パス金庫",
            Visible = true,
            Icon = File.Exists(iconPath) ? new Icon(iconPath) : SystemIcons.Shield
        };

        var menu = new Forms.ContextMenuStrip();
        menu.Items.Add("開く", null, (_, _) => ShowWindow());
        menu.Items.Add("ロック", null, (_, _) => _lockAction());
        menu.Items.Add("終了", null, (_, _) => ExitApplication());
        _notifyIcon.ContextMenuStrip = menu;
        _notifyIcon.DoubleClick += (_, _) => ShowWindow();
    }

    private void ShowWindow()
    {
        if (_window is PassKinko.App.MainWindow mainWindow)
        {
            mainWindow.ShowFromTray();
            return;
        }

        WindowPositionService.MoveToBottomLeft(_window);
        _window.Show();
        _window.WindowState = WindowState.Normal;
        _window.Activate();
    }

    private void ExitApplication()
    {
        if (_window is PassKinko.App.MainWindow mainWindow)
        {
            mainWindow.RequestApplicationExit();
        }
        Dispose();
        System.Windows.Application.Current.Shutdown();
    }

    public void Dispose()
    {
        _notifyIcon.Visible = false;
        _notifyIcon.Dispose();
    }
}
