using System.Windows;

namespace PassKinko.App.Services;

public static class WindowPositionService
{
    public static void MoveToBottomLeft(Window window)
    {
        var workArea = SystemParameters.WorkArea;
        window.Left = workArea.Left + 16;
        window.Top = workArea.Bottom - window.Height - 16;
    }
}
