using System.Text;

namespace Password_Manager;
using System;
using System.IO;
using System.Text.RegularExpressions;
using System.Security.Cryptography;
using System.Diagnostics;

public static class Asp
{
    public static void SetFolderHidden(string folderPath)
    {
        if (Directory.Exists(folderPath))
        {
            FileAttributes attributes = File.GetAttributes(folderPath);
            
            attributes |= FileAttributes.Hidden;

            File.SetAttributes(folderPath, attributes);
        }
    }
    
    public static (string sanitizedUsername, string sanitizedPassword) SanitizeUserInput(string username, string password)
    {
        username = username.Trim();
        password = password.Trim();
        
        username = Regex.Replace(username, @"[^a-zA-Z0-9_]", "");
        
        password = Regex.Replace(password, @"\s", "");

        return (username, password);
    }
    
    public static byte[] GenerateSalt(int size = 16)
    {
        var salt = new byte[size];
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(salt);
        }
        return salt;
    }
    
    public static byte[] ComputeSaltedHash(string password, byte[] salt)
    {
        using var sha256 = SHA256.Create();
        byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
        byte[] passwordWithSalt = new byte[passwordBytes.Length + salt.Length];

        Buffer.BlockCopy(passwordBytes, 0, passwordWithSalt, 0, passwordBytes.Length);
        Buffer.BlockCopy(salt, 0, passwordWithSalt, passwordBytes.Length, salt.Length);

        return sha256.ComputeHash(passwordWithSalt);
    }

    public static void AddUser(string username, string salt, string hash)
    {
        string passwordsFile = Path.Combine(Folders.PasswordManagerFolder, "Passwords.txt");
        string backupFile = Path.Combine(Folders.PasswordManager, "Passwords.txt");
        
        if (!File.Exists(Folders.PasswordManagerFolder))
        {
            File.Create(passwordsFile).Close();
        }
        if (!File.Exists(Folders.PasswordManagerFolder))
        {
            string mainPass = Path.Combine(Folders.PasswordManagerFolder, "Passwords.txt");
            File.Create(mainPass).Close();
        }
        
        string entry = $"{username}:{salt}:{hash}";
        
        File.AppendAllText(passwordsFile, entry + Environment.NewLine);
        File.AppendAllText(backupFile, entry + Environment.NewLine);
    }

    public static Dictionary<string, (string Salt, string Hash)> LoadUsers(string filePath)
    {
        var users = new Dictionary<string, (string Salt, string Hash)>();

        if (!File.Exists(filePath))
        {
            return users; // return empty dictionary
        }

        string[] lines = File.ReadAllLines(filePath);

        foreach (string line in lines)
        {
            if (string.IsNullOrWhiteSpace(line))
                continue;
            
            string[] parts = line.Split(':');

            if (parts.Length != 3)
            {
                Console.WriteLine($"Warning: Invalid line format -> '{line}'");
                continue;
            }

            string username = parts[0].Trim();
            string salt = parts[1].Trim();
            string hash = parts[2].Trim();

            if (!users.ContainsKey(username))
            {
                users.Add(username, (Salt: salt, Hash: hash));
            }
        }
        return users;
    }
    
    public static bool HashesMatch(byte[] a, byte[] b)
    {
        if (a.Length != b.Length)
            return false;

        bool match = true;

        for (int i = 0; i < a.Length; i++)
            match &= (a[i] == b[i]);

        return match;
    }
    
    public static string SanitizeInput(string input, string type)
    {
        if (string.IsNullOrEmpty(input))
            return "";

        switch (type.ToLower())
        {
            case "website":
                return Regex.Replace(input, "[^A-Za-z]", "");

            case "username":
                return Regex.Replace(input, "[^A-Za-z0-9_]", "");

            case "password":
                input = Regex.Replace(input, @"[\s:]+", "");
                
                StringBuilder sb = new StringBuilder();
                foreach (char c in input)
                {
                    if (char.IsLetterOrDigit(c))
                    {
                        sb.Append(c);
                    }
                    else
                    {
                        sb.Append('\\').Append(c); // prepend backslash
                    }
                }
                return sb.ToString();

            default:
                throw new ArgumentException("Unknown input type");
        }
    }

    private static byte[] Protect(byte[] data)
    {
        return ProtectedData.Protect(data, null, DataProtectionScope.CurrentUser);
    }

    private static byte[] Unprotect(byte[] data)
    {
        return ProtectedData.Unprotect(data, null, DataProtectionScope.CurrentUser);
    }
    
    public static void GenerateAndStoreAesKeyIv(string username)
    {
        string folderMain = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "---P4sswordManagerSecure"
        );

        string folderUser = Path.Combine(folderMain, username);

        Directory.CreateDirectory(folderMain);
        Directory.CreateDirectory(folderUser);
        SetFolderHidden(folderMain);
        Folders.RemoveTags(folderMain);

        string keyPath = Path.Combine(folderUser, "aes.key");
        string ivPath  = Path.Combine(folderUser, "aes.iv");
        
        if (File.Exists(keyPath) && File.Exists(ivPath))
            return;

        using (Aes aes = Aes.Create())
        {
            aes.KeySize = 256; // strongest AES

            byte[] protectedKey = Protect(aes.Key);
            byte[] protectedIv  = Protect(aes.IV);

            File.WriteAllBytes(keyPath, protectedKey);
            File.WriteAllBytes(ivPath, protectedIv);
        }
    }
    
    public static (bool success, byte[] key, byte[] iv) LoadAesKeyIv(string username)
    {
        string folder = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "PasswordManagerSecure",
            username
        );

        string keyPath = Path.Combine(folder, "aes.key");
        string ivPath  = Path.Combine(folder, "aes.iv");

        if (!File.Exists(keyPath) || !File.Exists(ivPath))
            return (false, null, null);

        byte[] protectedKey = File.ReadAllBytes(keyPath);
        byte[] protectedIv  = File.ReadAllBytes(ivPath);

        byte[] key = Unprotect(protectedKey);
        byte[] iv  = Unprotect(protectedIv);

        return (true, key, iv);
    }
    
    public static string EncryptString(string plaintext, byte[] key, byte[] iv)
    {
        using (Aes aes = Aes.Create())
        {
            aes.Key = key;
            aes.IV = iv;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;

            using (var encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
            using (var ms = new MemoryStream())
            using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
            using (var sw = new StreamWriter(cs))
            {
                sw.Write(plaintext);
                sw.Close();
                return Convert.ToBase64String(ms.ToArray());
            }
        }
    }
    
    public static string DecryptString(string ciphertextBase64, byte[] key, byte[] iv)
    {
        byte[] cipherBytes = Convert.FromBase64String(ciphertextBase64);

        using (Aes aes = Aes.Create())
        {
            aes.Key = key;
            aes.IV = iv;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;

            using (var decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
            using (var ms = new MemoryStream(cipherBytes))
            using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
            using (var sr = new StreamReader(cs))
            {
                return sr.ReadToEnd();
            }
        }
    }
    
    public static void LogUserCreation(string username)
    {
        try
        {
            string logDirectory = Path.Combine(Folders.PasswordManagerFolder, "Logs");
            Directory.CreateDirectory(logDirectory);

            string logFile = Path.Combine(logDirectory, "Log.txt");
            
            string logDirectoryBackup = Path.Combine(Folders.PasswordManager, "Logs");
            Directory.CreateDirectory(logDirectoryBackup);

            string logFileBackup = Path.Combine(logDirectoryBackup, "LogBackup.txt");

            string logEntry = $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} | Created user: {username}";

            File.AppendAllText(logFileBackup, logEntry + Environment.NewLine);
            File.AppendAllText(logFile, logEntry + Environment.NewLine);
        }
        catch (Exception ex)
        {
            Console.WriteLine("Failed to write user creation log: " + ex.Message);
        }
    }
    
    public static void LogLoginAttempt(string username, bool success, string reason = "")
    {
        try
        {
            string logDirectory = Path.Combine(Folders.PasswordManagerFolder, "Logs");
            Directory.CreateDirectory(logDirectory);

            string logFile = Path.Combine(logDirectory, "LoginAttempts.txt");
            
            string logDirectoryBackup = Path.Combine(Folders.PasswordManager, "Logs");
            Directory.CreateDirectory(logDirectoryBackup);

            string logFileBackup = Path.Combine(logDirectoryBackup, "LoginAttemptsBackup.txt");

            string status = success ? "SUCCESS" : "FAILED";

            string logEntry;

            if (string.IsNullOrWhiteSpace(reason))
            {
                logEntry = $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} | {status} | User: {username}";
            }
            else
            {
                logEntry = $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} | {status} | Reason: {reason}";
            }

            File.AppendAllText(logFile, logEntry + Environment.NewLine);
            File.AppendAllText(logFileBackup, logEntry + Environment.NewLine);
        }
        catch (Exception ex)
        {
            Console.WriteLine("Error writing login log: " + ex.Message);
        }
    }
    public static void LogManagedPasswordAddition(string accountOwner, string website)
    {
        try
        {
            string logDir = Path.Combine(Folders.PasswordManagerFolder, "Logs");
            Directory.CreateDirectory(logDir);

            string logFile = Path.Combine(logDir, "ManagedPasswordActions.txt");
            
            string logDirBackup = Path.Combine(Folders.PasswordManager, "Logs");
            Directory.CreateDirectory(logDirBackup);

            string logFileBackup = Path.Combine(logDirBackup, "ManagedPasswordActionsBackup.txt");

            string logEntry = $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} | ADD | User: {accountOwner} | Website: {website}";

            File.AppendAllText(logFile, logEntry + Environment.NewLine);
            File.AppendAllText(logFileBackup, logEntry + Environment.NewLine);
        }
        catch (Exception ex)
        {
            Console.WriteLine("Error writing password addition log: " + ex.Message);
        }
    }
    public static void LogManagedPasswordDeletion(string accountOwner, string website)
    {
        try
        {
            string logDir = Path.Combine(Folders.PasswordManagerFolder, "Logs");
            Directory.CreateDirectory(logDir);

            string logFile = Path.Combine(logDir, "ManagedPasswordActions.txt");
            
            string logDirBackup = Path.Combine(Folders.PasswordManager, "Logs");
            Directory.CreateDirectory(logDirBackup);

            string logFileBackup = Path.Combine(logDirBackup, "ManagedPasswordActionsBackup.txt");

            string logEntry = $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} | DELETE | User: {accountOwner} | Website: {website}";

            File.AppendAllText(logFile, logEntry + Environment.NewLine);
            File.AppendAllText(logFileBackup, logEntry + Environment.NewLine);
        }
        catch (Exception ex)
        {
            Console.WriteLine("Error writing password deletion log: " + ex.Message);
        }
    }
}