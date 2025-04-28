using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Xml;
using Microsoft.Win32;
using GodInfo.Utils;
using System.Linq;
using System.Diagnostics;

namespace GodInfo.Commands
{
    public class CommandHistoryInfoCommand : ICommand
    {
        public void Execute(List<string> args)
        {
            Logger.TaskHeader("Command History Information", 1);
            Logger.WriteLine("[*] Collecting command history information from various sources...");
            
            CollectPowerShellHistory();
            CollectCmdHistory();
            CollectConsoleLogs();
            CollectPSReadLineHistory();
        }
        
        private void CollectPowerShellHistory()
        {
            Logger.TaskHeader("PowerShell Command History", 2);
            
            try
            {
                string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
                string psHistoryPath = Path.Combine(userProfile, @"AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt");
                
                if (File.Exists(psHistoryPath))
                {
                    List<string> uniqueCommands = new List<string>();
                    string[] historyLines = File.ReadAllLines(psHistoryPath);
                    
                    foreach (string cmd in historyLines)
                    {
                        if (!string.IsNullOrWhiteSpace(cmd) && !uniqueCommands.Contains(cmd))
                        {
                            uniqueCommands.Add(cmd);
                        }
                    }
                    
                    Logger.WriteLine($"[+] Found {uniqueCommands.Count} unique PowerShell commands in history");
                    
                    // 创建表格数据
                    List<string> headers = new List<string> { "Command" };
                    List<List<string>> rows = new List<List<string>>();
                    
                    foreach (string cmd in uniqueCommands.Take(100)) // 限制显示的数量
                    {
                        rows.Add(new List<string> { cmd });
                    }
                    
                    // 打印表格
                    Logger.PrintTable(headers, rows);
                    
                    if (uniqueCommands.Count > 100)
                    {
                        Logger.WriteLine($"[*] Showing only 100 of {uniqueCommands.Count} commands. Full list saved to log file.");
                    }
                }
                else
                {
                    Logger.WriteLine("[-] PowerShell history file not found");
                }
            }
            catch (Exception ex)
            {
                Logger.WriteLine($"[-] Error collecting PowerShell history: {ex.Message}");
            }
        }
        
        private void CollectCmdHistory()
        {
            Logger.TaskHeader("CMD Command History (From Registry)", 2);
            
            try
            {
                using (RegistryKey key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"))
                {
                    if (key != null)
                    {
                        string[] valueNames = key.GetValueNames();
                        
                        List<KeyValuePair<string, string>> cmdHistory = new List<KeyValuePair<string, string>>();
                        
                        foreach (string valueName in valueNames)
                        {
                            if (valueName != "MRUList")
                            {
                                string command = (string)key.GetValue(valueName);
                                // 移除命令末尾的MRU标记
                                if (command.EndsWith("\0"))
                                {
                                    command = command.Substring(0, command.Length - 1);
                                }
                                cmdHistory.Add(new KeyValuePair<string, string>(valueName, command));
                            }
                        }
                        
                        // 根据MRUList排序
                        string mruList = (string)key.GetValue("MRUList");
                        if (!string.IsNullOrEmpty(mruList))
                        {
                            List<KeyValuePair<string, string>> sortedHistory = new List<KeyValuePair<string, string>>();
                            foreach (char c in mruList)
                            {
                                var item = cmdHistory.FirstOrDefault(x => x.Key == c.ToString());
                                if (!string.IsNullOrEmpty(item.Value))
                                {
                                    sortedHistory.Add(item);
                                }
                            }
                            cmdHistory = sortedHistory;
                        }
                        
                        if (cmdHistory.Count > 0)
                        {
                            Logger.WriteLine($"[+] Found {cmdHistory.Count} entries in Run command history");
                            
                            // 创建表格数据
                            List<string> headers = new List<string> { "Order", "Command" };
                            List<List<string>> rows = new List<List<string>>();
                            
                            for (int i = 0; i < cmdHistory.Count; i++)
                            {
                                rows.Add(new List<string> { cmdHistory[i].Key, cmdHistory[i].Value });
                            }
                            
                            // 打印表格
                            Logger.PrintTable(headers, rows);
                        }
                        else
                        {
                            Logger.WriteLine("[-] No Run command history found");
                        }
                    }
                    else
                    {
                        Logger.WriteLine("[-] Run command history registry key not found");
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.WriteLine($"[-] Error collecting CMD history from registry: {ex.Message}");
            }
        }
        
        private void CollectConsoleLogs()
        {
            Logger.TaskHeader("Console Command History (From Event Logs)", 2);
            
            try
            {
                // 这个方法需要管理员权限才能访问所有事件日志
                if (!CommonUtils.IsAdminRight())
                {
                    Logger.WriteLine("[-] Administrator privileges required for full event log access");
                }
                
                ProcessStartInfo psi = new ProcessStartInfo
                {
                    FileName = "wevtutil.exe",
                    Arguments = "qe Microsoft-Windows-PowerShell/Operational /c:10 /rd:true /f:text",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    CreateNoWindow = true
                };
                
                using (Process process = Process.Start(psi))
                {
                    string output = process.StandardOutput.ReadToEnd();
                    process.WaitForExit();
                    
                    if (!string.IsNullOrEmpty(output))
                    {
                        // 简单解析输出以提取命令
                        List<string> commandLines = new List<string>();
                        foreach (string line in output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
                        {
                            if (line.Contains("CommandLine:") || line.Contains("ScriptBlock text ="))
                            {
                                int index = line.IndexOf("CommandLine:") > -1 ? 
                                    line.IndexOf("CommandLine:") + "CommandLine:".Length : 
                                    line.IndexOf("ScriptBlock text =") + "ScriptBlock text =".Length;
                                
                                if (index > 0 && index < line.Length)
                                {
                                    string cmd = line.Substring(index).Trim();
                                    if (!string.IsNullOrWhiteSpace(cmd))
                                    {
                                        commandLines.Add(cmd);
                                    }
                                }
                            }
                        }
                        
                        if (commandLines.Count > 0)
                        {
                            Logger.WriteLine($"[+] Found {commandLines.Count} command entries in PowerShell event logs");
                            
                            // 创建表格数据
                            List<string> headers = new List<string> { "Command from Event Log" };
                            List<List<string>> rows = new List<List<string>>();
                            
                            foreach (string cmd in commandLines)
                            {
                                rows.Add(new List<string> { cmd });
                            }
                            
                            // 打印表格
                            Logger.PrintTable(headers, rows);
                        }
                        else
                        {
                            Logger.WriteLine("[-] No command history found in event logs");
                        }
                    }
                    else
                    {
                        Logger.WriteLine("[-] No output from event log query");
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.WriteLine($"[-] Error collecting command history from event logs: {ex.Message}");
            }
        }
        
        private void CollectPSReadLineHistory()
        {
            Logger.TaskHeader("PSReadLine History (Multiple User Profiles)", 2);
            
            try
            {
                // 检查所有用户的PowerShell历史记录
                string usersFolder = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "..", "Users");
                
                if (Directory.Exists(usersFolder))
                {
                    int totalHistoryFiles = 0;
                    
                    foreach (string userDir in Directory.GetDirectories(usersFolder))
                    {
                        string userHistoryPath = Path.Combine(userDir, @"AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt");
                        
                        if (File.Exists(userHistoryPath))
                        {
                            totalHistoryFiles++;
                            string userName = Path.GetFileName(userDir);
                            
                            try
                            {
                                string[] historyLines = File.ReadAllLines(userHistoryPath);
                                
                                if (historyLines.Length > 0)
                                {
                                    Logger.WriteLine($"[+] Found PowerShell history for user '{userName}' with {historyLines.Length} commands");
                                    
                                    // 创建表格数据
                                    List<string> headers = new List<string> { "User", "Command" };
                                    List<List<string>> rows = new List<List<string>>();
                                    
                                    // 限制为每个用户显示最近的20条命令
                                    foreach (string cmd in historyLines.Reverse().Take(20))
                                    {
                                        if (!string.IsNullOrWhiteSpace(cmd))
                                        {
                                            rows.Add(new List<string> { userName, cmd });
                                        }
                                    }
                                    
                                    // 打印表格
                                    Logger.PrintTable(headers, rows);
                                    
                                    if (historyLines.Length > 20)
                                    {
                                        Logger.WriteLine($"[*] Showing only the most recent 20 of {historyLines.Length} commands for user '{userName}'");
                                    }
                                }
                                else
                                {
                                    Logger.WriteLine($"[-] PowerShell history file exists for user '{userName}' but is empty");
                                }
                            }
                            catch (Exception ex)
                            {
                                Logger.WriteLine($"[-] Error reading PowerShell history for user '{userName}': {ex.Message}");
                            }
                        }
                    }
                    
                    if (totalHistoryFiles == 0)
                    {
                        Logger.WriteLine("[-] No PowerShell history files found for any user");
                    }
                }
                else
                {
                    Logger.WriteLine("[-] Users directory not found or not accessible");
                }
            }
            catch (Exception ex)
            {
                Logger.WriteLine($"[-] Error collecting PSReadLine history from user profiles: {ex.Message}");
            }
        }
    }
} 