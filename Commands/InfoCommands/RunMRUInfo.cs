using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.Win32;
using System.Security.Principal;
using GodInfo.Utils;

namespace GodInfo.Commands
{
    public class RunMRUInfoCommand : ICommand
    {
        public struct RunMRUItem
        {
            public string UserSID;
            public string UserName;
            public string Command;
            public string Order;
        }

        public void Execute(List<string> args)
        {
            Logger.TaskHeader("Run Command History (MRU)", 1);
            Logger.WriteLine("[*] Collecting Run command history (MRU) for all users...");
            
            List<RunMRUItem> allMruItems = CollectAllUsersMRU();
            
            if (allMruItems.Count > 0)
            {
                Logger.WriteLine($"[+] Found {allMruItems.Count} Run MRU entries across all users");
                Logger.PrintTableFromStructs(allMruItems);
                
                // 如果全局日志目录已设置，保存到CSV
                if (!string.IsNullOrEmpty(Logger.globalLogDirectory))
                {
                    Logger.WriteStructsToCsv(allMruItems, Logger.globalLogDirectory, "RunMRU_History.csv");
                    Logger.WriteLine($"[+] Run MRU history saved to: {Logger.globalLogDirectory}\\RunMRU_History.csv");
                }
            }
            else
            {
                Logger.WriteLine("[-] No Run MRU history found");
            }
        }

        private List<RunMRUItem> CollectAllUsersMRU()
        {
            List<RunMRUItem> mruItems = new List<RunMRUItem>();
            
            try
            {
                // 获取所有用户的SID
                RegistryKey users = Registry.Users;
                string[] userSids = users.GetSubKeyNames();
                
                foreach (string sid in userSids)
                {
                    // 跳过Classes子键和非用户SID
                    if (sid.Contains("Classes") || !sid.StartsWith("S-1-5-21"))
                    {
                        continue;
                    }
                    
                    string runMruPath = $"{sid}\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU";
                    RegistryKey runMruKey = users.OpenSubKey(runMruPath);
                    
                    if (runMruKey == null)
                    {
                        continue;
                    }
                    
                    string userName = ResolveUserNameFromSid(sid);
                    Logger.WriteLine($"[+] Found Run MRU history for user: {userName} ({sid})");
                    
                    // 尝试获取MRUList值，它包含命令的顺序
                    string mruOrder = string.Empty;
                    try
                    {
                        mruOrder = runMruKey.GetValue("MRUList")?.ToString() ?? string.Empty;
                    }
                    catch
                    {
                        // 如果获取MRUList失败，继续处理各个值
                    }
                    
                    if (!string.IsNullOrEmpty(mruOrder))
                    {
                        // 按MRUList指定的顺序处理
                        foreach (char orderChar in mruOrder)
                        {
                            string valueName = orderChar.ToString();
                            string command = runMruKey.GetValue(valueName)?.ToString() ?? string.Empty;
                            
                            if (!string.IsNullOrEmpty(command))
                            {
                                // 移除末尾的分隔符
                                command = command.Replace("\\1", "");
                                
                                mruItems.Add(new RunMRUItem
                                {
                                    UserSID = sid,
                                    UserName = userName,
                                    Command = command,
                                    Order = valueName
                                });
                            }
                        }
                    }
                    else
                    {
                        // 如果没有MRUList，直接获取所有值
                        foreach (string valueName in runMruKey.GetValueNames())
                        {
                            if (valueName != "MRUList")
                            {
                                string command = runMruKey.GetValue(valueName)?.ToString() ?? string.Empty;
                                
                                if (!string.IsNullOrEmpty(command))
                                {
                                    // 移除末尾的分隔符
                                    command = command.Replace("\\1", "");
                                    
                                    mruItems.Add(new RunMRUItem
                                    {
                                        UserSID = sid,
                                        UserName = userName,
                                        Command = command,
                                        Order = valueName
                                    });
                                }
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.WriteLine($"[-] Error collecting Run MRU history: {ex.Message}");
            }
            
            return mruItems;
        }
        
        private string ResolveUserNameFromSid(string sid)
        {
            try
            {
                SecurityIdentifier securityIdentifier = new SecurityIdentifier(sid);
                NTAccount ntAccount = (NTAccount)securityIdentifier.Translate(typeof(NTAccount));
                return ntAccount.Value;
            }
            catch
            {
                return "Unknown User";
            }
        }
        
        // 扩展功能：收集包括"TypedURLs"在内的其他MRU信息
        private List<TypedURLItem> CollectTypedURLs()
        {
            List<TypedURLItem> urlItems = new List<TypedURLItem>();
            
            try
            {
                RegistryKey users = Registry.Users;
                string[] userSids = users.GetSubKeyNames();
                
                foreach (string sid in userSids)
                {
                    // 跳过Classes子键和非用户SID
                    if (sid.Contains("Classes") || !sid.StartsWith("S-1-5-21"))
                    {
                        continue;
                    }
                    
                    string typedURLsPath = $"{sid}\\SOFTWARE\\Microsoft\\Internet Explorer\\TypedURLs";
                    RegistryKey typedURLsKey = users.OpenSubKey(typedURLsPath);
                    
                    if (typedURLsKey == null)
                    {
                        continue;
                    }
                    
                    string userName = ResolveUserNameFromSid(sid);
                    
                    // 获取所有URL条目
                    foreach (string valueName in typedURLsKey.GetValueNames())
                    {
                        string url = typedURLsKey.GetValue(valueName)?.ToString() ?? string.Empty;
                        
                        if (!string.IsNullOrEmpty(url))
                        {
                            urlItems.Add(new TypedURLItem
                            {
                                UserSID = sid,
                                UserName = userName,
                                URL = url,
                                Index = valueName
                            });
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.WriteLine($"[-] Error collecting typed URLs: {ex.Message}");
            }
            
            return urlItems;
        }
        
        // 扩展功能：定义TypedURLs结构
        public struct TypedURLItem
        {
            public string UserSID;
            public string UserName;
            public string URL;
            public string Index;
        }
    }
} 