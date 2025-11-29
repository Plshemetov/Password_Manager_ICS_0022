namespace Password_Manager;

public static class MainMenu
{
    public static void MainList()
    {
        Console.Clear();
        InactivityManager.ResetInactivityTimer();
        List<string[]> loadedPasswords = Passwords.LoadManagedPasswords(User.Username);
        string choice = "";
        string[] validOptions = ["1", "2", "3", "4"];

        do
        {
            MenuItems.DisplayMainMenuHeader();
            Console.WriteLine($"Logged in user: {User.Username}");
            Console.WriteLine("");
            Console.WriteLine("---------------");
            if (loadedPasswords.Count == 0)
            {
                Console.WriteLine("It seams there are no passwords.");
            }
            else
            {
                foreach (var password in loadedPasswords)
                {
                    if (password.Length == 3)
                    {
                        Console.WriteLine($"{password[0]} | {password[1]} | {password[2]}");
                    }
                    else if (password.Length == 2)
                    {
                        Console.WriteLine($"{password[0]} | {password[1]}");
                    }
                }
            }
            
            Console.WriteLine("---------------");
            Console.WriteLine("");
            Console.WriteLine("1) Add password");
            Console.WriteLine("2) Delete password");
            Console.WriteLine("3) Exit");
            Console.WriteLine("");
            Console.Write(">: ");

            choice = Console.ReadLine().Trim();

            switch (choice)
            {
                case "1":
                    InactivityManager.ResetInactivityTimer();
                    Passwords.AddPassword(User.Username);
                    break;
                case "2":
                    InactivityManager.ResetInactivityTimer();
                    Passwords.DeletePassword(User.Username);
                    break;
                case "3":
                    Console.WriteLine("Exiting application...");
                    Environment.Exit(0);
                    break;
                default:
                    Console.WriteLine("Incorrect input.");
                    break;
            }
        } while (Array.IndexOf(validOptions, choice) == -1);
    }
}