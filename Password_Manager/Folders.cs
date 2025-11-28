using System.Security.AccessControl;

namespace Password_Manager;

public static class Folders
{
    public static string PasswordManagerFolder
    {
        get
        {
            string folder = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "---P4sswordManger"
            );
            Directory.CreateDirectory(folder);
            Asp.SetFolderHidden(folder);
            RemoveTags(folder);
            return folder;
        }
    }
    
    public static string UsersFolder
    {
        get
        {
            string folder = Path.Combine(PasswordManagerFolder, "Users");
            Directory.CreateDirectory(folder);
            RemoveTags(folder);
            return folder;
        }
    }

    public static string PasswordManager
    {
        get
        {
            string folder = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "---P4sswordMangerBackup"
            );
            Directory.CreateDirectory(folder);
            Asp.SetFolderHidden(folder);
            RemoveTags(folder);
            return folder;
        }
    }

    public static void RemoveTags(string folder)
    {
        var dirInfo = new DirectoryInfo(folder);
#pragma warning disable CA1416
        var security = dirInfo.GetAccessControl();
#pragma warning restore CA1416
        
#pragma warning disable CA1416
        security.RemoveAccessRule(
            new FileSystemAccessRule(
                "Everyone",
                FileSystemRights.Delete | FileSystemRights.DeleteSubdirectoriesAndFiles,
                AccessControlType.Allow));
#pragma warning restore CA1416

#pragma warning disable CA1416
        dirInfo.SetAccessControl(security);
#pragma warning restore CA1416
    }

    public static void CreateUserFolder(string username)
    {
        try
        {
            var userFolder = Path.Combine(UsersFolder, username);
            var backup = Path.Combine(PasswordManager, username);
            
            Directory.CreateDirectory(userFolder);
            Directory.CreateDirectory(backup);
            
            RemoveTags(userFolder);
            RemoveTags(backup);
            
            var managedPasswordsPath = Path.Combine(userFolder, "Managed_passwords.txt");
            
            var managedPasswordsPathBackup = Path.Combine(backup, "Managed_passwords.txt");
            
            if (!File.Exists(managedPasswordsPath))
                File.Create(managedPasswordsPath).Close();
            
            if (!File.Exists(managedPasswordsPathBackup))
                File.Create(managedPasswordsPathBackup).Close();
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error creating user folder/files: {ex.Message}");
        }
    }
}