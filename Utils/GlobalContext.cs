using GodInfo.Commands;
using System.Collections.Generic;

namespace GodInfo.Utils
{
    internal class GlobalContext
    {
        public static List<SoftwareInfoCommand.SoftwareInfo> InstalledSoftware { get; set; } = new List<SoftwareInfoCommand.SoftwareInfo>();
        public static List<ProcessCommand.ProcessInfo> RunningProcesses { get; set; } = new List<ProcessCommand.ProcessInfo>(); 

    }
}