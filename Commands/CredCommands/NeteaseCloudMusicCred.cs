using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using GodInfo.Utils;

namespace GodInfo.Commands
{
    public class NeteaseCloudMusicCredCommand : ICommand
    {
        public struct NeteaseCloudMusicInfo
        {
            public string UserId;
            public string ProfileURL;
            public string ConfigPath;
        }

        public void Execute(List<string> args)
        {
            Logger.TaskHeader("Credentials Mode", 1);
            Logger.WriteLine("[*] Hunting for NeteaseCloudMusic credentials");
            GetNeteaseCloudMusicInfo();
        }

        public static void GetNeteaseCloudMusicCred()
        {
            new NeteaseCloudMusicCredCommand().Execute(new List<string>());
        }

        private void GetNeteaseCloudMusicInfo()
        {
            Logger.TaskHeader("NeteaseCloudMusic Credentials", 2);

            List<NeteaseCloudMusicInfo> results = new List<NeteaseCloudMusicInfo>();

            try
            {
                // 网易云音乐主配置目录
                string configDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Netease\\CloudMusic");
                string infoPath = Path.Combine(configDir, "info");

                if (!File.Exists(infoPath))
                {
                    Logger.WriteLine("[-] NeteaseCloudMusic info file not found at: " + infoPath);
                    return;
                }

                Logger.WriteLine("[+] Found NeteaseCloudMusic config at: " + infoPath);

                // 读取用户ID信息
                string userId = File.ReadAllText(infoPath).Trim();
                if (string.IsNullOrEmpty(userId))
                {
                    Logger.WriteLine("[-] NeteaseCloudMusic user ID is empty");
                    return;
                }

                // 构建网易云音乐个人主页URL
                string profileUrl = "https://music.163.com/#/user/home?id=" + userId;

                // 尝试获取更多配置文件中的信息
                string loginCache = Path.Combine(configDir, "cache\\login.json");
                string loginConfig = Path.Combine(configDir, "config\\user.config");

                // 添加基本信息到结果
                NeteaseCloudMusicInfo musicInfo = new NeteaseCloudMusicInfo
                {
                    UserId = userId,
                    ProfileURL = profileUrl,
                    ConfigPath = configDir
                };
                results.Add(musicInfo);

                // 输出信息
                Logger.WriteLine("[+] Found NeteaseCloudMusic user ID: " + userId);
                Logger.WriteLine("[+] User profile URL: " + profileUrl);

                // 提取登录缓存信息（如果存在）
                if (File.Exists(loginCache))
                {
                    string loginCacheContent = File.ReadAllText(loginCache);
                    // 可以从JSON中提取更多信息，这里简化处理
                    Logger.WriteLine("[+] Found login cache file: " + loginCache);
                    
                    // 使用正则表达式尝试提取用户名/电话号码
                    Match phoneMatch = Regex.Match(loginCacheContent, @"""phone""\s*:\s*""([^""]+)""");
                    if (phoneMatch.Success && phoneMatch.Groups.Count > 1)
                    {
                        Logger.WriteLine("[+] Found phone number: " + phoneMatch.Groups[1].Value);
                    }
                    
                    Match usernameMatch = Regex.Match(loginCacheContent, @"""nickname""\s*:\s*""([^""]+)""");
                    if (usernameMatch.Success && usernameMatch.Groups.Count > 1)
                    {
                        Logger.WriteLine("[+] Found nickname: " + usernameMatch.Groups[1].Value);
                    }
                }

                // 输出配置文件的路径信息
                string outputDir = Path.Combine(Logger.globalLogDirectory, "NeteaseCloudMusic");
                Directory.CreateDirectory(outputDir);

                // 创建一个网易云音乐个人主页的快捷方式
                string shortcutContent = "[InternetShortcut]\r\nURL=" + profileUrl;
                File.WriteAllText(Path.Combine(outputDir, "NeteaseCloudMusic_profile.url"), shortcutContent, Encoding.UTF8);
                Logger.WriteLine("[+] Created profile shortcut at: " + Path.Combine(outputDir, "NeteaseCloudMusic_profile.url"));

                // 输出总结表格
                Logger.WriteLine("\n[+] NeteaseCloudMusic credentials summary:");
                Logger.PrintTableFromStructs(results);
            }
            catch (Exception ex)
            {
                Logger.WriteLine("[-] Error retrieving NeteaseCloudMusic info: " + ex.Message);
            }
        }

        // 检查网易云音乐配置是否存在
        public static bool CheckNeteaseCloudMusicExists()
        {
            string infoPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Netease\\CloudMusic\\info");
            return File.Exists(infoPath);
        }
    }
} 