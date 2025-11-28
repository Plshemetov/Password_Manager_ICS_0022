namespace Password_Manager;



public class User
{ 
    public static string Username { get; set; }
    private static string Password { get; set; }
    private static string confPass { get; set; }

    private static Dictionary<string, (string Salt, string hash)> _existingUsers;
    
    public static void RegisterUser()
    {
        Console.Clear();
        MenuItems.DisplayRegistrationHeader();
        bool isValid = false;
        
        if (File.Exists(Path.Combine(Folders.PasswordManagerFolder, "Passwords.txt")))
        {
            _existingUsers = Asp.LoadUsers(Path.Combine(Folders.PasswordManagerFolder, "Passwords.txt"));
        }
        else
        {
            _existingUsers = Asp.LoadUsers(Path.Combine(Folders.PasswordManager, "Passwords.txt"));
        }

        do
        {
            Console.Write("Username (Min 5) (Max 20): ");
            Username = Console.ReadLine();

            if (string.IsNullOrEmpty(Username))
            {
                Console.WriteLine("Invalid input. Please enter a valid username.\n");
                continue;
            }

            if (Username.Length is < 5 or > 20)
            {
                Console.WriteLine("Invalid username length.");
                continue;
            }
            
            Console.Write("Password (Min 5) (Max 20): ");
            Password = Console.ReadLine();

            if (string.IsNullOrEmpty(Password))
            {
                Console.WriteLine("Invalid input. Please enter a valid password.\n");
                continue;
            }

            if (Password.Length < 5 || Password.Length > 20)
            {
                Console.WriteLine("Invalid password length.");
                continue;
            }

            
            Console.Write("Confirm password: ");
            confPass = Console.ReadLine();

            if (string.IsNullOrEmpty(confPass))
            {
                Console.WriteLine("Invalid input. Please enter a valid password.\n");
                continue;
            }

            if (confPass != Password)
            {
                Console.WriteLine("Passwords don't match. Try again!\n");
                continue;
            }
            
            var sanitized = Asp.SanitizeUserInput(Username, Password);
            
            if (_existingUsers.ContainsKey(sanitized.sanitizedUsername))
            {
                Console.WriteLine("This username already exists. Please choose another.\n");
                continue;
            }

            // All checks passed
            isValid = true;

        } while (!isValid);

        var sanitized1 = Asp.SanitizeUserInput(Username, Password);
        
        byte[] salt = Asp.GenerateSalt();
        byte[] hash = Asp.ComputeSaltedHash(sanitized1.sanitizedPassword, salt);
        
        string saltBase64 = Convert.ToBase64String(salt);
        string hashBase64 = Convert.ToBase64String(hash);
        
        Asp.AddUser(sanitized1.sanitizedUsername, saltBase64, hashBase64);
        
        Console.WriteLine("Registration successful.");
        Username = sanitized1.sanitizedUsername;
        Password = "";
        confPass = "";
        
        Folders.CreateUserFolder(sanitized1.sanitizedUsername);
        
        Asp.GenerateAndStoreAesKeyIv(Username);
        
        Asp.LogUserCreation(Username);
        
        _existingUsers.Clear();
        
        Thread.Sleep(3000);
        Console.Clear();
    }

    public static void Login()
    {
        Console.Clear();
        MenuItems.DisplayLoginHeader();

        int attempts = 0;
        
        if (File.Exists(Path.Combine(Folders.PasswordManagerFolder, "Passwords.txt")))
        {
            _existingUsers = Asp.LoadUsers(Path.Combine(Folders.PasswordManagerFolder, "Passwords.txt"));
        }
        else
        {
            _existingUsers = Asp.LoadUsers(Path.Combine(Folders.PasswordManager, "Passwords.txt"));
        }
        
        bool isValid = false;

        do
        {
            Console.Write("Username: ");
            Username = Console.ReadLine();

            if (string.IsNullOrEmpty(Username))
            {
                Console.WriteLine("Invalid input. Try again!");
                Asp.LogLoginAttempt(Username, false, "Incorrect provision of credentials");
                attempts++;
                if (attempts == 3)
                {
                    Console.WriteLine("Number of tries exceeded. Quiting application");
                    Environment.Exit(0);
                }
                continue;
            }
            
            Console.Write("Password: ");
            string enteredPassword = Console.ReadLine();
            
            var sanitized = Asp.SanitizeUserInput(Username, enteredPassword);
            
            if (!_existingUsers.ContainsKey(sanitized.sanitizedUsername))
            {
                Console.WriteLine("Incorrect credentials. Try again");
                Asp.LogLoginAttempt(Username, false, "Trying to log into nonexistent user");
                attempts++;
                if (attempts == 3)
                {
                    Console.WriteLine("Number of tries exceeded. Quiting application");
                    Environment.Exit(0);
                }
                continue;
            }

            var (storedSaltBase64, storedHashBase64) = _existingUsers[sanitized.sanitizedUsername];

            if (storedHashBase64 == "" || storedSaltBase64 == "") 
            {
                Console.WriteLine("Corrupted user record.");
                continue;
            }
            
            byte[] storedSalt = Convert.FromBase64String(storedSaltBase64);
            byte[] storedHash = Convert.FromBase64String(storedHashBase64);
            
            if (string.IsNullOrEmpty(sanitized.sanitizedPassword))
            {
                Console.WriteLine("Invalid input. Try again!");
                Asp.LogLoginAttempt(Username, false, "Incorrect provision of credentials");
                attempts++;
                if (attempts == 3)
                {
                    Console.WriteLine("Number of tries exceeded. Quiting application");
                    Environment.Exit(0);
                }
                continue;
            }

            
            byte[] enteredHash = Asp.ComputeSaltedHash(sanitized.sanitizedPassword, storedSalt);

            if (!Asp.HashesMatch(enteredHash, storedHash))
            {
                Console.WriteLine("Incorrect credential. Try again!");
                Asp.LogLoginAttempt(Username, false, "Incorrect provision of credentials");
                attempts++;
                if (attempts == 3)
                {
                    Console.WriteLine("Number of tries exceeded. Quiting application");
                    Environment.Exit(0);
                }
                continue;
            }

            isValid = true;
        } while (!isValid);

        Console.WriteLine("Login successful!");
        Asp.LogLoginAttempt(Username, true, "");
        
        _existingUsers.Clear();
        
        Thread.Sleep(3000);
        Console.Clear();
    }
}