namespace Password_Manager;

public class Program
{
    public static void Main(String[] args)
    {
        //DisplayHeader();
        Asp.AddPassword("a", "a", "Test");
        
    }

    static void DisplayHeader()
    {
        Console.WriteLine("Password Manager");
        Console.WriteLine("__________________________");
    }
}