namespace Password_Manager;

public static class Login
{
    public static void EntryMenu()
    {
        string choice;
        string[] validOptions = ["1", "2", "3"];
        do
        {
            Console.Clear();
            MenuItems.DisplayHeader();
            Console.WriteLine("1) Register");
            Console.WriteLine("2) Login");
            Console.WriteLine("3) Exit");
            Console.WriteLine("");
            Console.Write(">: ");


            choice = Console.ReadLine().Trim();

            if (Array.IndexOf(validOptions, choice) == -1)
            {
                Console.WriteLine("Invalid option. Please select a valid menu item.");
                Console.WriteLine("Press any key to try again...");
                Console.ReadKey();
                continue;
            }

            switch (choice)
            {
                case "1":
                    InactivityManager.ResetInactivityTimer();
                    User.RegisterUser();
                    break;
                case "2":
                    InactivityManager.ResetInactivityTimer();
                    User.Login();
                    break;
                case "3":
                    Console.WriteLine("Exiting application...");
                    Environment.Exit(0);
                    break;
                default:
                    Console.WriteLine("Incorrect input");
                    break;
            }
        } while (Array.IndexOf(validOptions, choice) == -1);
    }
}