namespace Password_Manager;

public class Program
{
    public static void Main(String[] args)
    {
        InactivityManager.StartInactivityTimer();
        Login.EntryMenu();
        MainMenu.MainList();
    }
}