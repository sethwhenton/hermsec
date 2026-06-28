using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Text;

namespace GhazalCsharpApp
{
    class Program
    {
        // VULN 1: Hardcoded database credentials (CWE-798)
        private const string DB_HOST = "localhost";
        private const string DB_USER = "admin";
        private const string DB_PASS = "ghazal_csharp_db_pass!@#";

        // VULN 2: Hardcoded API key (CWE-798)
        private const string API_KEY = "ghazal-csharp-api-key-ck-1234567890abcdef";

        // VULN 3: SQL Injection via string concatenation (CWE-89)
        static string GetUser(string userId)
        {
            string query = "SELECT * FROM users WHERE id = '" + userId + "'";
            return ExecuteQuery(query);
        }

        // VULN 4: SQL Injection via string interpolation (CWE-89)
        static string SearchUsers(string name)
        {
            string query = $"SELECT * FROM users WHERE name LIKE '%{name}%'";
            return ExecuteQuery(query);
        }

        // VULN 5: Command Injection via Process.Start (CWE-78)
        static string PingHost(string host)
        {
            ProcessStartInfo psi = new ProcessStartInfo
            {
                FileName = "ping",
                Arguments = $"-n 4 {host}",
                RedirectStandardOutput = true,
                UseShellExecute = false
            };
            Process proc = Process.Start(psi);
            return proc.StandardOutput.ReadToEnd();
        }

        // VULN 6: Command Injection via cmd.exe (CWE-78)
        static string RunCommand(string command)
        {
            ProcessStartInfo psi = new ProcessStartInfo
            {
                FileName = "cmd.exe",
                Arguments = $"/c {command}",
                RedirectStandardOutput = true,
                UseShellExecute = false
            };
            Process proc = Process.Start(psi);
            return proc.StandardOutput.ReadToEnd();
        }

        // VULN 7: Path Traversal (CWE-22)
        static string ReadFile(string filename)
        {
            string filepath = Path.Combine("data", filename);
            return File.ReadAllText(filepath);
        }

        // VULN 8: Path Traversal via File.ReadAllText (CWE-22)
        static string DownloadFile(string file)
        {
            string fullPath = Path.Combine("/var/uploads", file);
            return File.ReadAllText(fullPath);
        }

        // VULN 9: XSS via string concatenation (CWE-79)
        static string SearchPage(string query)
        {
            return $"<html><body><h1>Search: {query}</h1></body></html>";
        }

        // VULN 10: Weak hash MD5 (CWE-328)
        static string HashPassword(string password)
        {
            using (MD5 md5 = MD5.Create())
            {
                byte[] bytes = md5.ComputeHash(Encoding.UTF8.GetBytes(password));
                StringBuilder sb = new StringBuilder();
                foreach (byte b in bytes)
                {
                    sb.Append(b.ToString("x2"));
                }
                return sb.ToString();
            }
        }

        // VULN 11: Hardcoded connection string (CWE-798)
        static string GetConnectionString()
        {
            return $"Server={DB_HOST};Database=ghazaldb;User Id={DB_USER};Password={DB_PASS};";
        }

        // VULN 12: Information exposure (CWE-209)
        static string HandleError()
        {
            try
            {
                throw new Exception("Something went wrong");
            }
            catch (Exception ex)
            {
                return $"Error: {ex.Message}\nStack: {ex.StackTrace}";
            }
        }

        static string ExecuteQuery(string query)
        {
            // Placeholder for database execution
            return $"Executed: {query}";
        }

        static void Main(string[] args)
        {
            Console.WriteLine("Ghazal C# Vulnerable App");
            Console.WriteLine(GetUser("1"));
            Console.WriteLine(SearchUsers("test"));
            Console.WriteLine(HandleError());
        }
    }
}
