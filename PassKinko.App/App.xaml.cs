using System;
using System.Threading;
using System.Windows;
using PassKinko.App.Services;

namespace PassKinko.App;

public partial class App : System.Windows.Application
{
    private const string MutexName = @"Local\PassKinko_SingleInstance";
    private const string ShowWindowEventName = @"Local\PassKinko_ShowWindow";

    private Mutex? _singleInstanceMutex;
    private bool _ownsMutex;
    private EventWaitHandle? _showWindowEvent;
    private Thread? _showWindowThread;

    protected override void OnStartup(StartupEventArgs e)
    {
        _showWindowEvent = new EventWaitHandle(false, EventResetMode.AutoReset, ShowWindowEventName);

        _singleInstanceMutex = new Mutex(true, MutexName, out var createdNew);
        _ownsMutex = createdNew;

        if (!createdNew)
        {
            try
            {
                _showWindowEvent.Set();
            }
            catch
            {
                // If signaling fails, just exit this second instance.
            }

            Shutdown();
            return;
        }

        StartShowWindowListener();

        base.OnStartup(e);

        var window = new MainWindow();
        MainWindow = window;

        WindowPositionService.MoveToBottomLeft(window);
        window.Show();
    }

    private void StartShowWindowListener()
    {
        _showWindowThread = new Thread(() =>
        {
            while (true)
            {
                try
                {
                    _showWindowEvent?.WaitOne();

                    Dispatcher.Invoke(() =>
                    {
                        if (MainWindow == null)
                        {
                            return;
                        }

                        if (MainWindow.Visibility != Visibility.Visible)
                        {
                            MainWindow.Show();
                        }

                        if (MainWindow.WindowState == WindowState.Minimized)
                        {
                            MainWindow.WindowState = WindowState.Normal;
                        }

                        MainWindow.Activate();
                        MainWindow.Topmost = true;
                        MainWindow.Topmost = false;
                        MainWindow.Focus();
                    });
                }
                catch
                {
                    break;
                }
            }
        });

        _showWindowThread.IsBackground = true;
        _showWindowThread.Start();
    }

    protected override void OnExit(ExitEventArgs e)
    {
        if (_ownsMutex)
        {
            try
            {
                _singleInstanceMutex?.ReleaseMutex();
            }
            catch
            {
                // Ignore release errors during shutdown.
            }
        }

        _singleInstanceMutex?.Dispose();
        _showWindowEvent?.Dispose();

        base.OnExit(e);
    }
}