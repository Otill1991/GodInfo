using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using System.Text;
using System.Windows.Forms;
using GodInfo.Utils;

namespace GodInfo.Commands
{
    public class ClipboardInfoCommand : ICommand
    {
        public struct ClipboardData
        {
            public string DataType;
            public string Content;
            public string FilePath;
        }

        public void Execute(List<string> args)
        {
            Logger.TaskHeader("Info Mode", 1);
            Logger.WriteLine("[*] Collecting clipboard contents.");
            GetClipboardInfo();
        }

        public static void GetClipboardInfo()
        {
            Logger.TaskHeader("Clipboard Contents", 1);
            
            try
            {
                List<ClipboardData> dataItems = new List<ClipboardData>();
                string outputDir = Path.Combine(Logger.globalLogDirectory, "Clipboard");
                Directory.CreateDirectory(outputDir);
                
                // 检查并处理文本数据
                bool hasText = false;
                var textCheckThread = new System.Threading.Thread(() => {
                    try
                    {
                        hasText = Clipboard.ContainsText();
                    }
                    catch (Exception ex)
                    {
                        Logger.WriteLine($"[-] Error checking text in clipboard: {ex.Message}");
                    }
                });
                textCheckThread.SetApartmentState(System.Threading.ApartmentState.STA);
                textCheckThread.Start();
                textCheckThread.Join();
                
                if (hasText)
                {
                    string text = string.Empty;
                    var textThread = new System.Threading.Thread(() => {
                        try
                        {
                            text = Clipboard.GetText();
                        }
                        catch (Exception ex)
                        {
                            Logger.WriteLine($"[-] Error retrieving text from clipboard: {ex.Message}");
                        }
                    });
                    textThread.SetApartmentState(System.Threading.ApartmentState.STA);
                    textThread.Start();
                    textThread.Join();
                    
                    if (!string.IsNullOrEmpty(text))
                    {
                        string textFilePath = Path.Combine(outputDir, "Clipboard_Text.txt");
                        File.WriteAllText(textFilePath, text, Encoding.UTF8);
                        
                        // 限制显示内容长度，避免过长文本
                        string displayText = text;
                        if (displayText.Length > 100)
                        {
                            displayText = displayText.Substring(0, 100) + "...";
                        }
                        
                        dataItems.Add(new ClipboardData
                        {
                            DataType = "Text",
                            Content = displayText,
                            FilePath = textFilePath
                        });
                        
                        Logger.WriteLine($"[+] Text content found in clipboard and saved to: {textFilePath}");
                    }
                }
                
                // 检查并处理RTF数据
                bool hasRtf = false;
                var rtfCheckThread = new System.Threading.Thread(() => {
                    try
                    {
                        hasRtf = Clipboard.ContainsData(DataFormats.Rtf);
                    }
                    catch (Exception ex)
                    {
                        Logger.WriteLine($"[-] Error checking RTF in clipboard: {ex.Message}");
                    }
                });
                rtfCheckThread.SetApartmentState(System.Threading.ApartmentState.STA);
                rtfCheckThread.Start();
                rtfCheckThread.Join();
                
                if (hasRtf)
                {
                    string rtfText = string.Empty;
                    var rtfThread = new System.Threading.Thread(() => {
                        try
                        {
                            rtfText = (string)Clipboard.GetData(DataFormats.Rtf);
                        }
                        catch (Exception ex)
                        {
                            Logger.WriteLine($"[-] Error retrieving RTF from clipboard: {ex.Message}");
                        }
                    });
                    rtfThread.SetApartmentState(System.Threading.ApartmentState.STA);
                    rtfThread.Start();
                    rtfThread.Join();
                    
                    if (!string.IsNullOrEmpty(rtfText))
                    {
                        string rtfFilePath = Path.Combine(outputDir, "Clipboard_Rtf.rtf");
                        File.WriteAllText(rtfFilePath, rtfText, Encoding.UTF8);
                        
                        dataItems.Add(new ClipboardData
                        {
                            DataType = "Rich Text",
                            Content = "RTF formatted text (see file)",
                            FilePath = rtfFilePath
                        });
                        
                        Logger.WriteLine($"[+] Rich text content found in clipboard and saved to: {rtfFilePath}");
                    }
                }
                
                // 检查并处理HTML数据
                bool hasHtml = false;
                var htmlCheckThread = new System.Threading.Thread(() => {
                    try
                    {
                        hasHtml = Clipboard.ContainsData(DataFormats.Html);
                    }
                    catch (Exception ex)
                    {
                        Logger.WriteLine($"[-] Error checking HTML in clipboard: {ex.Message}");
                    }
                });
                htmlCheckThread.SetApartmentState(System.Threading.ApartmentState.STA);
                htmlCheckThread.Start();
                htmlCheckThread.Join();
                
                if (hasHtml)
                {
                    string htmlText = string.Empty;
                    var htmlThread = new System.Threading.Thread(() => {
                        try
                        {
                            htmlText = (string)Clipboard.GetData(DataFormats.Html);
                        }
                        catch (Exception ex)
                        {
                            Logger.WriteLine($"[-] Error retrieving HTML from clipboard: {ex.Message}");
                        }
                    });
                    htmlThread.SetApartmentState(System.Threading.ApartmentState.STA);
                    htmlThread.Start();
                    htmlThread.Join();
                    
                    if (!string.IsNullOrEmpty(htmlText))
                    {
                        string htmlFilePath = Path.Combine(outputDir, "Clipboard_Html.html");
                        File.WriteAllText(htmlFilePath, htmlText, Encoding.UTF8);
                        
                        dataItems.Add(new ClipboardData
                        {
                            DataType = "HTML",
                            Content = "HTML formatted content (see file)",
                            FilePath = htmlFilePath
                        });
                        
                        Logger.WriteLine($"[+] HTML content found in clipboard and saved to: {htmlFilePath}");
                    }
                }
                
                // 检查并处理位图数据
                bool hasImage = false;
                var imageCheckThread = new System.Threading.Thread(() => {
                    try
                    {
                        hasImage = Clipboard.ContainsImage();
                    }
                    catch (Exception ex)
                    {
                        Logger.WriteLine($"[-] Error checking image in clipboard: {ex.Message}");
                    }
                });
                imageCheckThread.SetApartmentState(System.Threading.ApartmentState.STA);
                imageCheckThread.Start();
                imageCheckThread.Join();
                
                if (hasImage)
                {
                    Image image = null;
                    var imageThread = new System.Threading.Thread(() => {
                        try
                        {
                            image = Clipboard.GetImage();
                        }
                        catch (Exception ex)
                        {
                            Logger.WriteLine($"[-] Error retrieving image from clipboard: {ex.Message}");
                        }
                    });
                    imageThread.SetApartmentState(System.Threading.ApartmentState.STA);
                    imageThread.Start();
                    imageThread.Join();
                    
                    if (image != null)
                    {
                        string imageFilePath = Path.Combine(outputDir, "Clipboard_Image.jpg");
                        
                        try
                        {
                            image.Save(imageFilePath, ImageFormat.Jpeg);
                            
                            dataItems.Add(new ClipboardData
                            {
                                DataType = "Image",
                                Content = $"Image: {image.Width}x{image.Height}",
                                FilePath = imageFilePath
                            });
                            
                            Logger.WriteLine($"[+] Image content found in clipboard and saved to: {imageFilePath}");
                            
                            // 确保释放资源
                            image.Dispose();
                        }
                        catch (Exception ex)
                        {
                            Logger.WriteLine($"[-] Error saving image from clipboard: {ex.Message}");
                            if (image != null)
                            {
                                image.Dispose();
                            }
                        }
                    }
                }
                
                // 检查并处理文件列表数据
                bool hasFileDropList = false;
                var fileDropCheckThread = new System.Threading.Thread(() => {
                    try
                    {
                        hasFileDropList = Clipboard.ContainsFileDropList();
                    }
                    catch (Exception ex)
                    {
                        Logger.WriteLine($"[-] Error checking file drop list in clipboard: {ex.Message}");
                    }
                });
                fileDropCheckThread.SetApartmentState(System.Threading.ApartmentState.STA);
                fileDropCheckThread.Start();
                fileDropCheckThread.Join();
                
                if (hasFileDropList)
                {
                    System.Collections.Specialized.StringCollection fileDropList = null;
                    var fileDropThread = new System.Threading.Thread(() => {
                        try
                        {
                            fileDropList = Clipboard.GetFileDropList();
                        }
                        catch (Exception ex)
                        {
                            Logger.WriteLine($"[-] Error retrieving file drop list from clipboard: {ex.Message}");
                        }
                    });
                    fileDropThread.SetApartmentState(System.Threading.ApartmentState.STA);
                    fileDropThread.Start();
                    fileDropThread.Join();
                    
                    if (fileDropList != null && fileDropList.Count > 0)
                    {
                        string fileListPath = Path.Combine(outputDir, "Clipboard_Files.txt");
                        StringBuilder fileListBuilder = new StringBuilder();
                        
                        foreach (string file in fileDropList)
                        {
                            fileListBuilder.AppendLine(file);
                        }
                        
                        File.WriteAllText(fileListPath, fileListBuilder.ToString(), Encoding.UTF8);
                        
                        dataItems.Add(new ClipboardData
                        {
                            DataType = "File List",
                            Content = $"{fileDropList.Count} file(s) copied",
                            FilePath = fileListPath
                        });
                        
                        Logger.WriteLine($"[+] File list found in clipboard and saved to: {fileListPath}");
                    }
                }
                
                // 输出剪贴板内容摘要
                if (dataItems.Count > 0)
                {
                    Logger.WriteLine("\n[+] Clipboard data summary:");
                    Logger.PrintTableFromStructs(dataItems);
                }
                else
                {
                    Logger.WriteLine("[-] No supported data formats found in clipboard.");
                }
            }
            catch (Exception ex)
            {
                Logger.WriteLine($"[-] Error processing clipboard data: {ex.Message}");
                Logger.WriteLine($"    Stack Trace: {ex.StackTrace}");
            }
        }
    }
} 