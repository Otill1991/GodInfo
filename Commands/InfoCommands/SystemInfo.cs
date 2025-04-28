using System;
using System.IO;
using GodInfo.Utils;
using Microsoft.VisualBasic.Devices;
using System.Management;
using Microsoft.Win32;
using System.Text.RegularExpressions;
using System.Collections.Generic;
using System.Linq;
using System.Diagnostics;
using System.Text;

namespace GodInfo.Commands
{
    public class SystemAllInformations
    {
        public bool IsAdmin { get; set; }
        public string UserName { get; set; }
        public List<string> IPv4Addresses { get; set; }
        public string UserDomainName { get; set; }
        public string MachineName { get; set; }
        public string TimeZone { get; set; }
        public string LocalTime { get; set; }
        public string SystemInstallDate { get; set; }
        public string LastBootUpTime { get; set; }
        public string OSVersion { get; set; }
        public string[] Drives { get; set; }
        public string CurrentDirectory { get; set; }
        public string DotNetVersion { get; set; }
        public string BiosVersion { get; set; }
        public int ProcessorCount { get; set; }
        public double TotalPhysicalMemoryGB { get; set; }
        public double TotalDiskSizeGB { get; set; }
        public string ProcessorArchitecture { get; set; }
    }
    public class SystemInfoCommand : ICommand
    {
        public SystemAllInformations CollectSystemInfo()
        {
            TimeZone localZone = TimeZone.CurrentTimeZone;
            ComputerInfo computerInfo = new ComputerInfo();
            string[] logicalDrives = Environment.GetLogicalDrives();
            DriveInfo firstDrive = new DriveInfo(logicalDrives[0]);
            double totalSizeInGB = firstDrive.TotalSize / Math.Pow(1024, 3);
            List<string> ipv4Addresses = CommonUtils.GetValidIPv4Addresses();
            string biosVersion = "N/A";
            string systemInstallDate = "N/A";
            string lastBootUpTime = "N/A";

            try
            {
                using (ManagementObject Mobject = new ManagementClass("Win32_BIOS").GetInstances().OfType<ManagementObject>().FirstOrDefault())
                {
                    if (Mobject != null)
                    {
                        biosVersion = $"{Mobject["Manufacturer"]}";
                    }
                }

                using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_OperatingSystem"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        systemInstallDate = ManagementDateTimeConverter.ToDateTime(obj["InstallDate"].ToString()).ToString();
                        lastBootUpTime = ManagementDateTimeConverter.ToDateTime(obj["LastBootUpTime"].ToString()).ToString();
                    }
                }
            }
            catch
            {
                // Handle exceptions if necessary
            }
            SystemAllInformations sysInfo = new SystemAllInformations
            {
                IsAdmin = CommonUtils.IsAdminRight(),
                UserName = Environment.UserName,
                IPv4Addresses = ipv4Addresses,
                UserDomainName = Environment.UserDomainName,
                MachineName = Environment.MachineName,
                TimeZone = localZone.StandardName,
                LocalTime = DateTime.Now.ToLocalTime().ToString(),
                SystemInstallDate = systemInstallDate,
                LastBootUpTime = lastBootUpTime,
                OSVersion = computerInfo.OSFullName,
                Drives = logicalDrives,
                CurrentDirectory = Environment.CurrentDirectory,
                DotNetVersion = Environment.Version.ToString(),
                BiosVersion = biosVersion,
                ProcessorCount = Environment.ProcessorCount,
                TotalPhysicalMemoryGB = computerInfo.TotalPhysicalMemory / (1024 * 1024 * 1024),
                TotalDiskSizeGB = totalSizeInGB,
                ProcessorArchitecture = Environment.GetEnvironmentVariable("PROCESSOR_ARCHITECTURE")
            };
            return sysInfo;
        }


        public void Execute(List<string> args)
        {
            SystemAllInformations sysInfo = CollectSystemInfo();

            GetSysBasicInfo();
            GetUserAccounts();
            GetDefenderExclusions();
            Get360TrustList();
            Environment_Variable();
            DotNet_Version();
            QWinSta();
        }

        public void GetSysBasicInfo()
        {
            SystemAllInformations sysInfo = CollectSystemInfo();

            Logger.TaskHeader("Collecting Target Machine Information", 1);
            Logger.WriteLine("IsAdmin：" + sysInfo.IsAdmin);
            Logger.WriteLine("Whoami: " + sysInfo.UserName);
            Logger.WriteLine("IPv4Addr: {0}", string.Join(" ", sysInfo.IPv4Addresses.ToArray()));
            Logger.WriteLine("Domain: " + sysInfo.UserDomainName);
            Logger.WriteLine("HostName: " + sysInfo.MachineName);
            Logger.WriteLine("TimeZone: " + sysInfo.TimeZone);
            Logger.WriteLine("LocalTime: " + sysInfo.LocalTime);
            Logger.WriteLine("OSVersion: " + sysInfo.OSVersion);
            Logger.WriteLine("OSInstall: " + sysInfo.SystemInstallDate);
            Logger.WriteLine("LastBootUp: " + sysInfo.LastBootUpTime);
            Logger.WriteLine("Drives: {0}", string.Join(", ", sysInfo.Drives));
            Logger.WriteLine("Path: " + sysInfo.CurrentDirectory);
            Logger.WriteLine("DotNet: {0}", sysInfo.DotNetVersion);
            Logger.WriteLine("BIOS: " + sysInfo.BiosVersion);
            Logger.WriteLine("CPUS: {0} Count  MEMS: {1} GB", sysInfo.ProcessorCount, sysInfo.TotalPhysicalMemoryGB);
            Logger.WriteLine("Disk: {0} GB", sysInfo.TotalDiskSizeGB.ToString("0.00"));
            Logger.WriteLine("Arch: " + sysInfo.ProcessorArchitecture);
        }

        public static string GetAntivirus()
        {
            try
            {
                using (var antiVirusSearch = new ManagementObjectSearcher(
                           @"\\" + Environment.MachineName + @"\root\SecurityCenter2",
                           "Select * from AntivirusProduct"))
                {
                    var av = new List<string>();
                    foreach (var searchResult in antiVirusSearch.Get())
                        av.Add(searchResult["displayName"].ToString());
                    if (av.Count == 0) return "Not installed";
                    return string.Join(", ", av.ToArray()) + "";
                }
            }
            catch
            {
                // ignored
            }

            return "N/A";
        }


        public static void GetDefenderExclusions()
        {
            Logger.TaskHeader("Defender Exclusions", 1);
            Logger.WriteLine("Antivirus: {0}\n", GetAntivirus());
            if (!CommonUtils.IsAdminRight())
            {
                Logger.WriteLine("[-] Administrator privileges required!");
                return;
            }
            RegistryKey exclusions = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows Defender\Exclusions");

            if (exclusions == null)
            {
                Logger.WriteLine("[-] No exclusions specified");
            }
            else
            {
                foreach (string subKeyName in exclusions.GetSubKeyNames())
                {
                    RegistryKey subKey = exclusions.OpenSubKey(subKeyName);
                    Logger.WriteLine($"[*] {subKeyName}:");
                    if (subKey.ValueCount > 0)
                    {
                        foreach (string valueName in subKey.GetValueNames())
                        {
                            Logger.WriteLine($"    {valueName}");
                        }
                    }
                    else
                    {
                        Logger.WriteLine("    No values.");
                    }
                }
            }
        }

        public static void GetUserAccounts()
        {
            List<List<string>> rows = new List<List<string>>();
            Logger.TaskHeader("UserAccount", 1);
            // 创建表头
            List<string> headers = new List<string> { "Domain", "Name", "Status", "SID" };

            ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT * FROM Win32_UserAccount");
            foreach (ManagementObject user in searcher.Get())
            {

                List<string> row = new List<string>
                {
                    (string)user["Domain"],
                    (string)user["Name"],
                    (string)user["Status"],
                    (string)user["SID"]
                };
                rows.Add(row);
            }
            Logger.PrintTable(headers, rows);
        }

        public static void DotNet_Version()
        {
            Logger.WriteLine("[+] Microsoft.NET Versions Installed:\n");
            string[] Netdirectories = Directory.GetDirectories(@"C:\Windows\Microsoft.NET\Framework");
            for (int i = 0; i < Netdirectories.Length; i++)
            {
                Logger.WriteLine("  " + Netdirectories[i]);
            }
            //Logger.WriteLine("");
        }

        public static void Environment_Variable()
        {
            string path = "Environment";
            Logger.TaskHeader("Environment Variable", 1);
            Logger.WriteLine("[+] System Environment Variable Path:\n");

            RegistryKey masterKey = Registry.CurrentUser.OpenSubKey(path);
            if (masterKey != null)
            {
                object pathValue = masterKey.GetValue("Path");
                if (pathValue != null)
                {
                    string sPath = pathValue.ToString();
                    string[] sArray = Regex.Split(sPath, ";", RegexOptions.IgnoreCase);
                    foreach (string i in sArray)
                    {
                        Logger.WriteLine("  " + i);
                    }
                }
                else
                {
                    Logger.WriteLine("[-] 'Path' environment variable not found.");
                }
                masterKey.Close();
            }
            else
            {
                Logger.WriteLine("[-] Could not open registry key for environment variables.");
            }

            Logger.WriteLine("");
        }

        public static void QWinSta()
        {
            Logger.TaskHeader("Remote Desktop Sessions (QWinSta)", 1);
            
            try
            {
                // 创建进程启动信息
                ProcessStartInfo psi = new ProcessStartInfo
                {
                    FileName = "qwinsta",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    CreateNoWindow = true
                };

                // 启动进程并获取输出
                using (Process process = Process.Start(psi))
                {
                    // 读取标准输出
                    string output = process.StandardOutput.ReadToEnd();
                    process.WaitForExit();

                    if (string.IsNullOrEmpty(output))
                    {
                        Logger.WriteLine("[-] No remote desktop sessions found or command not available.");
                        return;
                    }

                    // 解析输出
                    List<string> headers = new List<string>();
                    List<List<string>> rows = new List<List<string>>();
                    
                    string[] lines = output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
                    
                    if (lines.Length > 0)
                    {
                        // 处理标题行
                        string headerLine = lines[0].Trim();
                        // 寻找标题之间的空格作为分隔符
                        List<int> columnPositions = new List<int>();
                        bool inWord = false;
                        
                        for (int i = 0; i < headerLine.Length; i++)
                        {
                            if (headerLine[i] != ' ' && !inWord)
                            {
                                inWord = true;
                                columnPositions.Add(i);
                            }
                            else if (headerLine[i] == ' ' && inWord)
                            {
                                inWord = false;
                            }
                        }
                        
                        // 使用列位置提取标题
                        for (int i = 0; i < columnPositions.Count; i++)
                        {
                            int startPos = columnPositions[i];
                            int endPos = (i < columnPositions.Count - 1) ? columnPositions[i + 1] : headerLine.Length;
                            
                            while (startPos < headerLine.Length && startPos < endPos && headerLine[startPos] == ' ')
                                startPos++;
                                
                            string header = headerLine.Substring(startPos, Math.Min(endPos - startPos, headerLine.Length - startPos)).Trim();
                            headers.Add(header);
                        }
                        
                        // 处理数据行
                        for (int lineIndex = 1; lineIndex < lines.Length; lineIndex++)
                        {
                            string line = lines[lineIndex].Trim();
                            if (string.IsNullOrEmpty(line)) continue;
                            
                            List<string> row = new List<string>();
                            
                            // 根据之前确定的列位置提取单元格内容
                            for (int i = 0; i < columnPositions.Count; i++)
                            {
                                int startPos = columnPositions[i];
                                int endPos = (i < columnPositions.Count - 1) ? columnPositions[i + 1] : line.Length;
                                
                                if (startPos >= line.Length)
                                {
                                    row.Add(string.Empty);
                                    continue;
                                }
                                
                                string cell = line.Substring(startPos, Math.Min(endPos - startPos, line.Length - startPos)).Trim();
                                row.Add(cell);
                            }
                            
                            // 确保行的单元格数等于标题数
                            while (row.Count < headers.Count)
                                row.Add(string.Empty);
                                
                            rows.Add(row);
                        }
                        
                        // 打印表格
                        Logger.PrintTable(headers, rows);
                    }
                    else
                    {
                        Logger.WriteLine("[-] No remote desktop sessions found.");
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.WriteLine($"[-] Error executing qwinsta command: {ex.Message}");
            }
        }

        public static void Get360TrustList()
        {
            Logger.TaskHeader("360 Security Trust Zone", 1);
            
            string appDataPath = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            string logDirectory = Path.Combine(appDataPath, @"360Safe\360ScanLog\");

            if (!Directory.Exists(logDirectory))
            {
                Logger.WriteLine("[-] 360 Security log directory not found: " + logDirectory);
                return;
            }

            Logger.WriteLine("[+] 360 Security log directory: " + logDirectory);
            
            // 分析360LogCenter日志
            Process360LogCenterFiles(logDirectory);
            
            // 分析ScanLog文件
            ProcessScanLogFiles(logDirectory);
        }

        private static void Process360LogCenterFiles(string logDirectory)
        {
            Logger.WriteLine("\n[*] Analyzing 360LogCenter logs...");

            var logFiles = Directory.GetFiles(logDirectory, "360LogCenter.exe.*.log")
                                   .OrderByDescending(f => File.GetLastWriteTime(f))
                                   .ToList();

            if (logFiles.Count == 0)
            {
                Logger.WriteLine("[-] No 360LogCenter log files found");
                return;
            }

            var latestLogFile = logFiles.First();
            Logger.WriteLine("[*] Analyzing latest log file: " + Path.GetFileName(latestLogFile));

            var whitelistEntries = new Dictionary<string, List<int>>();

            foreach (var line in File.ReadLines(latestLogFile))
            {
                var otcMatch = Regex.Match(line, @"otc=(\d+)");
                var fpMatch = Regex.Match(line, @"fp=([^\]]+)");

                if (otcMatch.Success && fpMatch.Success)
                {
                    int otcValue = int.Parse(otcMatch.Groups[1].Value);
                    string filePath = fpMatch.Groups[1].Value;
                    filePath = Environment.ExpandEnvironmentVariables(filePath);

                    if (!whitelistEntries.ContainsKey(filePath))
                    {
                        whitelistEntries[filePath] = new List<int>();
                    }

                    whitelistEntries[filePath].Add(otcValue);
                }
            }

            var confirmedWhitelist = new List<string>();
            foreach (var entry in whitelistEntries)
            {
                if (entry.Value.Count > 0 && entry.Value.Last() == 1)
                {
                    confirmedWhitelist.Add(entry.Key);
                }
            }

            if (confirmedWhitelist.Count > 0)
            {
                Logger.WriteLine("\n[+] Whitelist entries found in 360LogCenter logs:");
                foreach (var item in confirmedWhitelist.Distinct().OrderBy(x => x))
                {
                    Logger.WriteLine("    " + item);
                }
            }
            else
            {
                Logger.WriteLine("[-] No whitelist entries found in 360LogCenter logs");
            }
        }

        private static void ProcessScanLogFiles(string logDirectory)
        {
            Logger.WriteLine("\n[*] Analyzing ScanLog files...");

            var scanLogFiles = Directory.GetFiles(logDirectory, "ScanLog_*.txt")
                                       .OrderByDescending(f => File.GetLastWriteTime(f))
                                       .ToList();

            if (scanLogFiles.Count == 0)
            {
                Logger.WriteLine("[-] No ScanLog files found");
                return;
            }

            var allWhitelistItems = new HashSet<string>();
            var filesWithWhitelist = new List<string>();
            var filesWithoutWhitelist = new List<string>();

            foreach (var logFile in scanLogFiles)
            {
                var whitelistItems = ExtractWhitelistFromScanLog(logFile);
                if (whitelistItems.Count > 0)
                {
                    filesWithWhitelist.Add(Path.GetFileName(logFile));
                    foreach (var item in whitelistItems)
                    {
                        allWhitelistItems.Add(item);
                    }
                }
                else
                {
                    filesWithoutWhitelist.Add(Path.GetFileName(logFile));
                }
            }

            Logger.WriteLine(string.Format("\n[*] Analyzed {0} ScanLog files:", scanLogFiles.Count));
            Logger.WriteLine(string.Format("    - Files with whitelist: {0}", filesWithWhitelist.Count));
            Logger.WriteLine(string.Format("    - Files without whitelist: {0}", filesWithoutWhitelist.Count));

            if (allWhitelistItems.Count > 0)
            {
                Logger.WriteLine("\n[+] Whitelist settings found in ScanLog files (deduplicated):");
                foreach (var item in allWhitelistItems.OrderBy(x => x))
                {
                    Logger.WriteLine("    " + item);
                }
            }
            else
            {
                Logger.WriteLine("\n[-] No whitelist settings found in ScanLog files");
            }
        }

        private static List<string> ExtractWhitelistFromScanLog(string filePath)
        {
            var whitelistItems = new List<string>();
            var lines = File.ReadAllLines(filePath);
            bool inWhitelistSection = false;

            for (int i = 0; i < lines.Length; i++)
            {
                string line = lines[i].Trim();

                if (line.Contains("白名单设置"))
                {
                    inWhitelistSection = true;
                    i += 1;
                    continue;
                }

                if (inWhitelistSection)
                {
                    if (line.Contains("----------------------") || 
                        line.Contains("处理危险项") || 
                        line.Contains("扫描结果"))
                    {
                        break;
                    }

                    if (!string.IsNullOrWhiteSpace(line) &&
                        !line.StartsWith("-------") &&
                        !line.Contains("开始时间") &&
                        !line.Contains("使用时间") &&
                        !line.Contains("管理员"))
                    {
                        whitelistItems.Add(line);
                    }
                }
            }

            return whitelistItems;
        }
    }

}