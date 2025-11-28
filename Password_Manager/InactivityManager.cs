namespace Password_Manager;

using System;
using System.Timers;

public static class InactivityManager
{
    private static Timer _timer;
    private static readonly object _lock = new object();
    
    private static readonly TimeSpan Timeout = TimeSpan.FromMinutes(10);

    public static void StartInactivityTimer()
    {
        lock (_lock)
        {
            if (_timer != null)
                return;

            _timer = new Timer(Timeout.TotalMilliseconds);
            _timer.Elapsed += OnTimeout;
            _timer.AutoReset = false;
            _timer.Start();
        }
    }

    public static void ResetInactivityTimer()
    {
        lock (_lock)
        {
            if (_timer == null)
                return;

            _timer.Stop();
            _timer.Start();
        }
    }

    private static void OnTimeout(object sender, ElapsedEventArgs e)
    {
        Console.WriteLine("\n\nSession ended due to inactivity.");
        Environment.Exit(0);
    }
}
