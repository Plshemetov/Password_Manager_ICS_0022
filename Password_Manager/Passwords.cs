using System.Security.Cryptography;
using System.Text;

namespace Password_Manager;

public static class Passwords
{
    public static void AddPassword(string username)
    {
        bool confirm = false;
        do
        {
            Console.Clear();
            string randomPassword = GenerateRandomPassword();
            MenuItems.DisplayAddPasswordHeader();
            Console.WriteLine($"Suggested password: {randomPassword}");
            Console.WriteLine("Type in \"ESC\" at any point to return to main menu.");
            Console.WriteLine("");
            
            string website;
            string websitePassword;
            
            do
            {
                Console.WriteLine("Name of the website (without \".com\" or similar): ");
                website = Console.ReadLine().Trim();

                if (string.IsNullOrEmpty(website))
                {
                    Console.WriteLine("Website cannot be empty!");
                    continue;
                }

                if (website.Any(Char.IsDigit))
                {
                    Console.WriteLine("Website cannot contain numbers!");
                    continue;
                }

                if (website.Length > 128)
                {
                    continue;
                }

                if (website.Equals("ESC", StringComparison.CurrentCultureIgnoreCase))
                {
                    Console.WriteLine("Returning to the main menu");
                    Thread.Sleep(2000);
                    Console.Clear();
                    MainMenu.MainList();
                }
            } while (string.IsNullOrEmpty(website) || website.Any(Char.IsDigit));

            Console.WriteLine("Your username on that website (Can be empty): ");
            var websiteUser = Console.ReadLine().Trim();

            if (websiteUser.Length > 128)
            {
                continue;
            }
            if (websiteUser.Equals("ESC", StringComparison.CurrentCultureIgnoreCase))
            {
                Console.WriteLine("Returning to the main menu");
                Thread.Sleep(2000);
                Console.Clear();
                MainMenu.MainList();
            }
            
            do
            {
                Console.WriteLine("Password on that website: ");
                websitePassword = Console.ReadLine().Trim();

                if (string.IsNullOrEmpty(websitePassword))
                {
                    Console.WriteLine("Password cannot be empty!");
                    continue;
                }

                if (websitePassword.Length > 128)
                {
                    continue;
                }

                if (websitePassword.Equals("ESC", StringComparison.CurrentCultureIgnoreCase))
                {
                    Console.WriteLine("Returning to the main menu");
                    Thread.Sleep(2000);
                    Console.Clear();
                    MainMenu.MainList();
                }
            } while (string.IsNullOrEmpty(websitePassword));
            
            website = Asp.SanitizeInput(website, "website");
            
            if (!string.IsNullOrEmpty(websiteUser))
            {
                websiteUser = Asp.SanitizeInput(websiteUser, "username");
            }
            
            websitePassword = Asp.SanitizeInput(websitePassword, "password");

            if (!string.IsNullOrEmpty(websiteUser))
            {
                Console.WriteLine("");
                Console.WriteLine($"{website} | {websiteUser} | {websitePassword}");
                Console.WriteLine("");
            }
            else
            {
                Console.WriteLine("");
                Console.WriteLine($"{website} | {websitePassword}");
                Console.WriteLine("");
            }

            Console.WriteLine("Type \"Yes\" if everything is correct.\nType \"No\" if you want to change information");
            string choice;
            do
            {
                choice = Console.ReadLine().Trim().ToLower();
                if (choice == "yes")
                {
                    
                    confirm = true;
                    break;
                } 
            } while (choice is not ("yes" or "no"));

            if (confirm)
            {
                string basePath = Path.Combine(Folders.UsersFolder, username);

                string filePath = Path.Combine(basePath, "Managed_passwords.txt");

                string backup = Path.Combine(Folders.PasswordManager, username, "Managed_passwords.txt");
                string backupFile = Path.Combine(backup, "Managed_passwords.txt");

                List<string[]> existingEntries = LoadManagedPasswords(User.Username);

                Directory.CreateDirectory(basePath);
                Directory.CreateDirectory(backup);

                bool equalEntries = false;

                foreach (var existingEntry in existingEntries)
                {
                    if (equalEntries) break;
                    int length = existingEntry.Length;
                    switch (length)
                    {
                        case 2:
                            if (existingEntry[0].Equals(website, StringComparison.OrdinalIgnoreCase)
                                && existingEntry[1].Equals(websitePassword, StringComparison.OrdinalIgnoreCase))
                            {
                                Console.WriteLine("This entry already exist");
                                equalEntries = true;
                            }
                            break;
                        case 3:
                            if (existingEntry[0].Equals(website, StringComparison.OrdinalIgnoreCase)
                                && existingEntry[1].Equals(websiteUser, StringComparison.OrdinalIgnoreCase)
                                && existingEntry[2].Equals(websitePassword, StringComparison.OrdinalIgnoreCase))
                            {
                                Console.Clear();
                                Console.WriteLine("This entry already exist");
                                equalEntries = true;
                            }
                            break;
                    }
                }

                if (equalEntries)
                {
                    Console.WriteLine("Entry already exist!");
                    equalEntries = false;
                    confirm = false;
                    Thread.Sleep(2000);
                    continue;
                }
                
                string entry;
                
                if (!string.IsNullOrEmpty(websiteUser))
                {
                    entry = $"{website}:{websiteUser}:{websitePassword}";
                }
                else
                {
                    entry = $"{website}:{websitePassword}";
                }
                
                
                
                var result = Asp.LoadAesKeyIv(User.Username);
                if (!result.success)
                {
                    Console.WriteLine("Something went missing");
                    Thread.Sleep(2000);
                    MainMenu.MainList();
                }

                byte[] key = result.key;
                byte[] iv = result.iv;

                

                string encryptedString = Asp.EncryptString(entry, key, iv);

                try
                {
                    using (StreamWriter writer = new StreamWriter(filePath, append: true))
                    {
                        writer.WriteLine(encryptedString);
                    }
                    using (StreamWriter writer = new StreamWriter(backupFile, append: true))
                    {
                        writer.WriteLine(encryptedString);
                    }
                    Asp.LogManagedPasswordAddition(User.Username, website);
                    Console.WriteLine("Password added successfully.");
                    Thread.Sleep(2000);
                    MainMenu.MainList();
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error adding managed password: {ex.Message}");
                }
            }
        } while (!confirm);
    }

    public static void DeletePassword(string username)
    {
        Console.Clear();
        MenuItems.DisplayDeletePasswordHeader();
        Console.WriteLine("Type in \"Esc\" to go back to main menu.");
        bool confirm = false;

        do
        {
            string website;
            
            List<string[]> availableChoice = LoadManagedPasswords(User.Username);
            bool match = false;
            do
            {
                Console.WriteLine("Select a website for which you want to delete the entry: ");
                website = Console.ReadLine().Trim();
                if (string.IsNullOrEmpty(website) || website.Any(Char.IsDigit))
                {
                    Console.WriteLine("Invalid input. Try again!");
                    continue;
                }

                if (website.Length > 128)
                {
                    continue;
                }
                
                if (website.Equals("ESC", StringComparison.OrdinalIgnoreCase))
                {
                    Console.WriteLine("Going back to the main menu.");
                    availableChoice.Clear();
                    Thread.Sleep(2000);
                    MainMenu.MainList();
                }
                
                website = Asp.SanitizeInput(website, "website");
                foreach (var choice in availableChoice)
                {
                    if (choice[0].Equals(website))
                    {
                        match = true;
                        break;
                    }
                }

                if (!match)
                {
                    Console.WriteLine("No entry was found. Try again!");
                }
            } while (string.IsNullOrEmpty(website) || website.Any(Char.IsDigit) || !match);

            string password;
            int matchCount = -1;
            do
            {
                Console.WriteLine("Type in the password for this website: ");
                password = Console.ReadLine().Trim();

                if (string.IsNullOrEmpty(password))
                {
                    Console.WriteLine("Invalid input. Try again!");
                }

                if (password.Length > 128)
                {
                    continue;
                }
                
                password = Asp.SanitizeInput(password, "password");
                
                foreach (var entry in availableChoice)
                {
                    if (entry[1].Equals(password) && entry[0].Equals(website) && entry.Length == 2)
                    {
                        matchCount++;
                        break;
                    }
                    if (entry[2].Equals(password) && entry[0].Equals(website))
                    {
                        matchCount++;
                    } 
                }

                if (matchCount == -1)
                {
                    Console.WriteLine("Incorrect input. Try again!");
                    continue;
                }
               
                if (password.Equals("ESC", StringComparison.OrdinalIgnoreCase))
                {
                    Console.WriteLine("Going back to the main menu.");
                    availableChoice.Clear();
                    Thread.Sleep(2000);
                    MainMenu.MainList();
                }
            } while(string.IsNullOrEmpty(password));

            
            string user = null;

            if (matchCount == 0)
            {
                Console.WriteLine("Are you sure you want to delete it? (y/n): ");
                string userChoice;
                do
                {
                    userChoice = Console.ReadLine().Trim();
                    if (userChoice.Equals("y", StringComparison.OrdinalIgnoreCase))
                    {
                        confirm = true;
                        break;
                    }
                } while (!userChoice.Equals("y", StringComparison.OrdinalIgnoreCase) ||
                         !userChoice.Equals("n", StringComparison.OrdinalIgnoreCase));
                if (availableChoice.Count == 1)
                { 
                    List<string> emptyList = new List<string>();
                    
                    string basePath = Path.Combine(Folders.UsersFolder, username);
                    string filePath = Path.Combine(basePath, "Managed_passwords.txt");
                    string backup = Path.Combine(Folders.PasswordManager, username, "Managed_passwords.txt");
                    
                    File.WriteAllLines(filePath, emptyList);
                    File.WriteAllLines(backup, emptyList);
                    
                    Asp.LogManagedPasswordDeletion(User.Username, website);
                    availableChoice.Clear();
                    Console.WriteLine("Password deleted successfully!");
                    Thread.Sleep(2000);
                    MainMenu.MainList();
                }
            }
            else
            {
                bool matchUser = false;
                if (availableChoice.Count > 1){
                    do
                    {
                        Console.WriteLine("Type in the username used on that website: ");
                        user = Console.ReadLine().Trim();

                        if (user.Equals("ESC", StringComparison.OrdinalIgnoreCase))
                        {
                            Console.WriteLine("Going back to the main menu.");
                            availableChoice.Clear();
                            Thread.Sleep(2000);
                            MainMenu.MainList();
                        }

                        if (string.IsNullOrEmpty(user))
                        {
                            Console.WriteLine("Invalid input. Try again!");
                            continue;
                        }

                        if (user.Length > 128)
                        {
                            continue;
                        }

                        user = Asp.SanitizeInput(user, "username");
                    
                        foreach (var choice in availableChoice)
                        {
                            if (choice[0].Equals(website) && choice[1].Equals(user) && choice[2].Equals(password))
                            {
                                matchUser = true;
                                break;
                            }
                        }

                        if (!matchUser)
                        {
                            Console.WriteLine("No entry was found! Try again");
                        }

                    } while (!matchUser);
                    
                    Console.WriteLine("Are you sure you want to delete it? (y/n): ");
                    string userChoice;
                    do
                    {
                        userChoice = Console.ReadLine().Trim();
                        if (userChoice.Equals("y", StringComparison.OrdinalIgnoreCase))
                        {
                            confirm = true;
                            break;
                        }
                    } while (!userChoice.Equals("y", StringComparison.OrdinalIgnoreCase) ||
                             !userChoice.Equals("n", StringComparison.OrdinalIgnoreCase));
                }

                if (confirm)
                {
                    string basePath = Path.Combine(Folders.UsersFolder, username);
                    string filePath = Path.Combine(basePath, "Managed_passwords.txt");
                    
                    string backup = Path.Combine(Folders.PasswordManager, username, "Managed_passwords.txt");

                    if (!File.Exists(filePath))
                        return;
                    
                    if (!File.Exists(backup))
                        return;

                    var result = Asp.LoadAesKeyIv(User.Username);
                    if (!result.success)
                    {
                        Console.WriteLine("Something went missing");
                        Thread.Sleep(2000);
                        MainMenu.MainList();
                    }

                    byte[] key = result.key;
                    byte[] iv = result.iv;

                    List<string> remainingLines = new List<string>();

                    foreach (var rawLine in availableChoice)
                    {
                        string[] isMatch;
                        if (string.IsNullOrEmpty(user))
                        {
                            isMatch = [website, password];
                        }
                        else
                        {
                            isMatch = [website, user, password];
                        }

                        if (!rawLine.SequenceEqual(isMatch) && isMatch.Length == 2)
                        {
                            string entry = $"{website}:{password}";
                            remainingLines.Add(Asp.EncryptString(entry, key, iv));
                        }

                        if (!rawLine.SequenceEqual(isMatch) && isMatch.Length == 3)
                        {
                            string entry = $"{rawLine[0]}:{rawLine[1]}:{rawLine[2]}";
                            remainingLines.Add(Asp.EncryptString(entry, key, iv));
                        }
                    }

                    File.WriteAllLines(filePath, remainingLines);
                    File.WriteAllLines(backup, remainingLines);
                    Asp.LogManagedPasswordDeletion(User.Username, website);
                    availableChoice.Clear();
                    Console.WriteLine("Password deleted successfully!");
                    Thread.Sleep(2000);
                    MainMenu.MainList();
                }
            }
        } while (!confirm);
    }
    
    static string GenerateRandomPassword(int length = 12)
    {
        const string upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        const string lower = "abcdefghijklmnopqrstuvwxyz";
        const string digits = "0123456789";
        const string symbols = "!@#$%^&*()-_=+[]{}|;,.<>?";

        string allChars = upper + lower + digits + symbols;

        StringBuilder password = new StringBuilder();
        using (var rng = RandomNumberGenerator.Create())
        {
            byte[] buffer = new byte[4];

            for (int i = 0; i < length; i++)
            {
                rng.GetBytes(buffer);
                int index = BitConverter.ToInt32(buffer, 0) & int.MaxValue;
                password.Append(allChars[index % allChars.Length]);
            }
        }

        return password.ToString();
    }
    
    public static List<string[]> LoadManagedPasswords(string username)
    {
        string basePath = Path.Combine(
            Folders.UsersFolder,
            username
        );
        
        var loaded = Asp.LoadAesKeyIv(username);
        byte[] key = loaded.key;
        byte[] iv  = loaded.iv;

        string filePath = Path.Combine(basePath, "Managed_passwords.txt");
        
        if (!File.Exists(filePath))
            return [];

        List<string[]> results = new List<string[]>();
        
        foreach (string rawLine in File.ReadAllLines(filePath))
        {
            if (string.IsNullOrWhiteSpace(rawLine))
                continue;

            string encryptedLine = rawLine.Trim();

            string decrypted;

            try
            {
                decrypted = Asp.DecryptString(encryptedLine, key, iv);
            }
            catch
            {
                continue;
            }
            
            string[] parts = decrypted.Split(':');

            results.Add(parts); 
        }
        
        return results;
    }
}