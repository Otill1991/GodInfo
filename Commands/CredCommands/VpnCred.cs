using GodInfo.Utils;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace GodInfo.Commands
{
    class VpnCredCommand : ICommand
    {
        public void Execute(List<string> args)
        {
            Logger.TaskHeader("VPN Credential", 1);
            try
            {
                string vpnInfo = GetVpnConfig();
                if (!string.IsNullOrEmpty(vpnInfo))
                {
                    Console.WriteLine(vpnInfo);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] 提取VPN配置信息时发生错误: " + ex.Message);
            }
        }

        private string GetVpnConfig()
        {
            StringBuilder sb = new StringBuilder();
            
            string pbkPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                @"Microsoft\Network\Connections\Pbk\rasphone.pbk"
            );

            if (!File.Exists(pbkPath))
            {
                Logger.WriteLine("[-] 未找到VPN或拨号连接配置 (rasphone.pbk文件不存在)。");
                return null;
            }

            try
            {
                var entries = ParsePbkFile(pbkPath);
                
                if (entries.Count <= 0)
                {
                    Logger.WriteLine("[-] 未发现任何VPN配置项。");
                    return null;
                }
                
                Logger.WriteLine("[*] Hunted " + entries.Count + " VPN configurations:");
                
                foreach (var entry in entries)
                {
                    Logger.WriteLine("\n  [*] VPN名称: " + entry.Key);
                    Logger.WriteLine("  [*] 主机/电话: " + entry.Value);
                }

                // 复制配置文件到输出目录
                string outputDir = Path.Combine(Logger.globalLogDirectory, "VPN");
                Directory.CreateDirectory(outputDir);
                string outputFile = Path.Combine(outputDir, "rasphone.pbk");
                File.Copy(pbkPath, outputFile, true);
                Logger.WriteLine("\n[+] 获取解密密码: Dialupass.exe /stext pass.txt" );
                Logger.WriteLine("\n[+] VPN配置文件已复制到: " + outputFile);
            }
            catch (Exception ex)
            {
                Logger.WriteLine("[-] 解析VPN配置文件时出错: " + ex.Message);
                return null;
            }

            return sb.ToString();
        }

        private Dictionary<string, string> ParsePbkFile(string filePath)
        {
            var entries = new Dictionary<string, string>();
            string currentEntry = null;
            string phoneNumber = null;

            foreach (var line in File.ReadAllLines(filePath))
            {
                if (line.StartsWith("[") && line.EndsWith("]"))
                {
                    // 保存上一个条目
                    if (currentEntry != null && phoneNumber != null)
                    {
                        entries[currentEntry] = phoneNumber;
                    }
                    
                    // 开始新条目
                    currentEntry = line.Trim('[', ']');
                    phoneNumber = null;
                }
                else if (currentEntry != null && line.TrimStart().StartsWith("PhoneNumber="))
                {
                    phoneNumber = line.Split('=')[1].Trim();
                }
            }

            // 添加最后一个条目
            if (currentEntry != null && phoneNumber != null)
            {
                entries[currentEntry] = phoneNumber;
            }

            return entries;
        }
    }
} 