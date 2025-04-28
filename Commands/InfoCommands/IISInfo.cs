using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Linq;
using System.Text;
using GodInfo.Utils;

namespace GodInfo.Commands
{
    public class IISInfoCommand : ICommand
    {
        public struct IISSiteInfo
        {
            public string SiteID;
            public string SiteName;
            public string Bindings;
            public string PhysicalPath;
            public string AnonymousUser;
            public string AuthType;
            public string AppPoolName;
        }

        public void Execute(List<string> args)
        {
            Logger.TaskHeader("Info Mode", 1);
            Logger.WriteLine("[*] Collecting IIS server information.");
            CollectIISInfo();
        }

        public static void GetIISInfo()
        {
            new IISInfoCommand().Execute(new List<string>());
        }

        private void CollectIISInfo()
        {
            Logger.TaskHeader("IIS Information", 2);

            try
            {
                List<IISSiteInfo> sitesList = new List<IISSiteInfo>();
                List<AppPoolInfo> appPoolsList = new List<AppPoolInfo>();
                
                // 检查IIS是否安装
                bool iisInstalled = IsIISInstalled();
                if (!iisInstalled)
                {
                    Logger.WriteLine("[-] IIS is not installed on this system.");
                    return;
                }

                // 连接到 IIS W3SVC
                DirectoryEntry objService = new DirectoryEntry("IIS://localhost/W3SVC");
                Logger.WriteLine("[+] Connected to IIS service successfully.");
                
                int totalSites = 0;
                // 遍历所有子节点（网站）
                foreach (DirectoryEntry obj3w in objService.Children)
                {
                    string childObjectName = obj3w.Name;

                    // 检查是否是数字（网站ID）
                    int temp;
                    if (int.TryParse(childObjectName, out temp))
                    {
                        try
                        {
                            // 获取网站对象
                            DirectoryEntry IIs = objService.Children.Find(childObjectName, "IIsWebServer");

                            // 获取网站绑定信息
                            string serverBindings = GetPropertyValue(IIs, "ServerBindings");
                            string serverComment = GetPropertyValue(IIs, "ServerComment");
                            string appPoolId = GetPropertyValue(IIs, "AppPoolId");

                            // 获取根虚拟目录
                            DirectoryEntry IISweb = IIs.Children.Find("Root", "IIsWebVirtualDir");

                            // 获取匿名访问信息
                            string anonymousUser = GetPropertyValue(IISweb, "AnonymousUserName");
                            string anonymousPass = GetPropertyValue(IISweb, "AnonymousUserPass");
                            string path = GetPropertyValue(IISweb, "Path");
                            string authFlags = GetPropertyValue(IISweb, "AuthFlags");
                            
                            // 获取认证类型描述
                            string authType = GetAuthTypeDescription(authFlags);

                            // 格式化绑定信息以便于阅读
                            string formattedBindings = FormatBindings(serverBindings);

                            // 添加到网站列表
                            IISSiteInfo siteInfo = new IISSiteInfo
                            {
                                SiteID = childObjectName,
                                SiteName = serverComment,
                                Bindings = formattedBindings,
                                PhysicalPath = path,
                                AnonymousUser = anonymousUser,
                                AuthType = authType,
                                AppPoolName = appPoolId
                            };
                            
                            sitesList.Add(siteInfo);
                            totalSites++;

                            // 扫描虚拟目录（不打印详细信息，只收集到列表中）
                            CollectVirtualDirectories(IIs, childObjectName);
                        }
                        catch (Exception ex)
                        {
                            Logger.WriteLine($"[-] Error processing site {childObjectName}: {ex.Message}");
                            continue;
                        }
                    }
                }
                
                // 输出摘要表格
                if (sitesList.Count > 0)
                {
                    Logger.WriteLine($"[+] Total IIS Sites Found: {totalSites}");
                    Logger.WriteLine("[+] IIS Sites Summary:");
                    Logger.PrintTableFromStructs(sitesList);
                }
                else
                {
                    Logger.WriteLine("[-] No IIS sites found on this server.");
                }
                
                // 收集应用程序池信息
                CollectAppPoolInfo();
            }
            catch (Exception ex)
            {
                Logger.WriteLine($"[-] Error collecting IIS information: {ex.Message}");
            }
        }

        public struct AppPoolInfo
        {
            public string Name;
            public string State;
            public string DotNetVersion;
            public string Identity;
            public string UserName;
        }

        private void CollectVirtualDirectories(DirectoryEntry site, string siteId)
        {
            try
            {
                foreach (DirectoryEntry child in site.Children)
                {
                    if (child.SchemaClassName == "IIsWebVirtualDir" && child.Name != "Root")
                    {
                        // 可以在这里收集虚拟目录信息到列表，但不打印详细信息
                        CollectVirtualDirectories(child, siteId);
                    }
                }
            }
            catch (Exception)
            {
                // 静默处理异常
            }
        }

        private void CollectAppPoolInfo()
        {
            try
            {
                List<AppPoolInfo> appPoolsList = new List<AppPoolInfo>();
                
                DirectoryEntry appPools = new DirectoryEntry("IIS://localhost/W3SVC/AppPools");
                foreach (DirectoryEntry pool in appPools.Children)
                {
                    string poolName = pool.Name;
                    string managedRuntimeVersion = GetPropertyValue(pool, "ManagedRuntimeVersion");
                    string identityType = GetAppPoolIdentityType(GetPropertyValue(pool, "ProcessModel", "IdentityType"));
                    string userName = GetPropertyValue(pool, "ProcessModel", "UserName");
                    string state = GetPropertyValue(pool, "AppPoolState") == "2" ? "Running" : "Stopped";
                    
                    appPoolsList.Add(new AppPoolInfo
                    {
                        Name = poolName,
                        State = state,
                        DotNetVersion = managedRuntimeVersion,
                        Identity = identityType,
                        UserName = userName
                    });
                }

                if (appPoolsList.Count > 0)
                {
                    Logger.WriteLine("[+] Application Pools Summary:");
                    Logger.PrintTableFromStructs(appPoolsList);
                }
            }
            catch (Exception ex)
            {
                Logger.WriteLine($"[-] Error collecting Application Pool information: {ex.Message}");
            }
        }

        private string GetAppPoolIdentityType(string identityType)
        {
            switch (identityType)
            {
                case "0": return "Local System";
                case "1": return "Local Service";
                case "2": return "Network Service";
                case "3": return "Specific User";
                case "4": return "Application Pool Identity";
                default: return $"Unknown ({identityType})";
            }
        }

        private string GetPropertyValue(DirectoryEntry entry, string propertyName)
        {
            try
            {
                if (entry.Properties[propertyName].Value != null)
                {
                    return entry.Properties[propertyName].Value.ToString();
                }
            }
            catch { }
            return string.Empty;
        }

        private string GetPropertyValue(DirectoryEntry entry, string propertyCategory, string propertyName)
        {
            try
            {
                PropertyValueCollection valueCollection = entry.Properties[propertyCategory];
                if (valueCollection != null && valueCollection.Value != null)
                {
                    DirectoryEntry subEntry = (DirectoryEntry)valueCollection.Value;
                    if (subEntry.Properties[propertyName].Value != null)
                    {
                        return subEntry.Properties[propertyName].Value.ToString();
                    }
                }
            }
            catch { }
            return string.Empty;
        }

        private string GetAuthTypeDescription(string authFlags)
        {
            if (string.IsNullOrEmpty(authFlags))
                return "Unknown";
                
            int flags;
            if (!int.TryParse(authFlags, out flags))
                return authFlags;
                
            List<string> authTypes = new List<string>();
            
            if ((flags & 1) != 0) authTypes.Add("Anonymous");
            if ((flags & 2) != 0) authTypes.Add("Basic");
            if ((flags & 4) != 0) authTypes.Add("Windows");
            if ((flags & 8) != 0) authTypes.Add("Digest");
            
            return authTypes.Count > 0 ? string.Join(", ", authTypes) : "None";
        }

        private string FormatBindings(string bindings)
        {
            if (string.IsNullOrEmpty(bindings))
                return "";
                
            string[] bindingEntries = bindings.Split(':');
            List<string> formattedEntries = new List<string>();
            
            foreach (string entry in bindingEntries)
            {
                if (!string.IsNullOrEmpty(entry))
                {
                    string[] parts = entry.Split(':');
                    if (parts.Length >= 2)
                    {
                        // 处理可能的 hostname:port 格式
                        formattedEntries.Add($"{parts[0]}:{parts[1]}");
                    }
                    else
                    {
                        formattedEntries.Add(entry);
                    }
                }
            }
            
            return string.Join(", ", formattedEntries);
        }

        private bool IsIISInstalled()
        {
            try
            {
                DirectoryEntry iisService = new DirectoryEntry("IIS://localhost/W3SVC");
                iisService.RefreshCache();
                return true;
            }
            catch
            {
                return false;
            }
        }
    }
} 