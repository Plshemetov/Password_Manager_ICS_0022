using System.Text;

namespace Password_Manager;
using System.IO;

public class Asp
{
    //TODO: Add user input for the desired program and password

    private static string UserDirectory { get; set; }

    private static void GetUserDirectory()
    {
        UserDirectory = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
    }

    //Use this function to add passwords to the file
    public static void AddPassword(string password, string system, string username)
    {
        GetUserDirectory();
        if (!File.Exists(Path.Combine(UserDirectory, username + ".csv")))
        {
            string filename = Path.Combine(UserDirectory, username + ".csv");
            File.Create(filename);
        }
        string file = Path.Combine(UserDirectory, username + ".csv");
        
        StringBuilder csv = new StringBuilder(64);

        //TODO: Make new entries appear on new lines
        csv.AppendFormat("{0}; {1}; {2}", system, password, username);
        csv.Append(Environment.NewLine);
        
        File.AppendAllText(file, csv.ToString());
    }
}