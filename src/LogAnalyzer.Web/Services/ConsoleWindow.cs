using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace LogAnalyzer.Web.Services;

/// <summary>
/// When Visual Studio debugs the app it opens a console window that only shows the log - closing it stops
/// the app. This hides that window, but only when it is safe to do so:
///   - Windows, and a debugger is attached (F5 / green Start button; Ctrl+F5 keeps the window, because the
///     app could otherwise not be stopped),
///   - the console belongs to this app alone (Visual Studio's debug console host): a terminal used for
///     "dotnet run" is never hidden.
/// Logs remain visible in Visual Studio's Output window (Debug logger). Set LOGANALYZER_SHOW_CONSOLE=1 to keep it.
/// </summary>
internal static class ConsoleWindow
{
    private const int SwHide = 0;
    private const int SwShowMinNoActive = 7;
    private static readonly string[] VisualStudioHosts = ["VsDebugConsole", "devenv"];

    public static void HideWhenDebuggedByVisualStudio(IHostApplicationLifetime lifetime, ILogger logger)
    {
        if (!OperatingSystem.IsWindows() || !Debugger.IsAttached)
            return;
        if (Environment.GetEnvironmentVariable("LOGANALYZER_SHOW_CONSOLE") == "1")
            return;

        try
        {
            Hide(lifetime, logger);
        }
        catch (Exception ex)
        {
            // Purely cosmetic: never let this stop the app.
            logger.LogDebug(ex, "Could not hide the console window");
        }
    }

    [SupportedOSPlatform("windows")]
    private static void Hide(IHostApplicationLifetime lifetime, ILogger logger)
    {
        var window = GetConsoleWindow();
        if (window == IntPtr.Zero)
            return;

        var ids = new uint[16];
        var count = GetConsoleProcessList(ids, (uint)ids.Length);
        if (count == 0 || count > ids.Length)
            return;

        var self = (uint)Environment.ProcessId;
        for (var i = 0; i < count; i++)
        {
            if (ids[i] == self)
                continue;
            string name;
            try
            {
                name = Process.GetProcessById((int)ids[i]).ProcessName;
            }
            catch (ArgumentException)
            {
                continue; // process already exited
            }
            // Shared with a shell, "dotnet run" or anything else: leave the window alone.
            if (!VisualStudioHosts.Any(h => name.Equals(h, StringComparison.OrdinalIgnoreCase)))
                return;
        }

        ShowWindow(window, SwHide);
        logger.LogInformation("Console window hidden (debugging from Visual Studio). Logs are in the Output window.");

        // On a normal shutdown, give the window back (minimised) so Visual Studio's host can close it.
        lifetime.ApplicationStopping.Register(() => ShowWindow(window, SwShowMinNoActive));
    }

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetConsoleWindow();

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint GetConsoleProcessList([Out] uint[] processList, uint processCount);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
}
