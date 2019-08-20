/*
│ Emre Ekinci                                     
│ yunusemrem@windowslive.com	                                                         
│        
│      TODO:
                > Listeyi değişiklik olunca yenile
	            > listenin sadece değişikliklerini yenile		
	            > API lere kalan zaman değeri ver
                > response result ları bir class ta tut
*/
using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using HashChecker.Properties;
using Microsoft.Office.Interop.Outlook;
using OutlookApp = Microsoft.Office.Interop.Outlook.Application;
using Console = Colorful.Console;
using System.Text.RegularExpressions;

namespace HashChecker {
    public class MainClass {
        static string banner                = Resources.banner;
        static string hashFile              = "hashes.txt";
        static public Random random         = new Random();
        static public List<string> md5List  = new List<string>();
        static void Main(string[] args) {
            Console.OutputEncoding = Encoding.UTF8;
            Console.WriteFormatted(banner, Color.LightGoldenrodYellow);
            Api virusTotalAPI = new Api();
            virusTotalAPI.myProxySetting = Helpers.initializeProxyConfigs();

            Task liveBoard = null;
            try {
                md5List = new List<string>(File.ReadAllLines(hashFile));
                md5List = md5List.Select(s => String.Join("", s.Split(',', '\n', '\t'))).Distinct().ToList(); // clean dirty md5 list
                liveBoard = Task.Factory.StartNew(() => LiveBoard()); // run the liveboard to see results alive
                virusTotalAPI.checkHashes(md5List);

                liveBoard.Wait();
                Api.results = Api.results.OrderBy(ss => ss.resultMc).ToList();
            }
            catch (System.Exception e) {
                Console.WriteLineFormatted("\n | Exception: " + e.Message, Color.Red);
            }
            LiveBoard();//run again to show last results
            WriteToFile();
            WriteCsirtMail();
            WriteAtarMail();
            Console.SetCursorPosition(0, banner.Split('\n').ToList().Count + Api.results.Count + 3 );
            Console.WriteFormatted("\n__________________________________________  ALL DONE _______________________________________________ ", Color.LightGoldenrodYellow);
            Console.WriteFormatted("\n____________________________________________________________________________________________________ ", Color.LightGoldenrodYellow);
            Console.ReadLine();
            Environment.Exit(0);
        }
        /// <summary>
        /// 
        /// </summary>
        static void LiveBoard() {
            Console.Clear();
            string blank = new string('_', 28);
            Console.WriteFormatted(banner, Color.LightGoldenrodYellow);
            int dashBoardLen = Resources.banner.Split('\n').Count();
            int finished = 0;
            do {
                List<string> tempResults = Api.results.ToList();
                finished = Api.nFinished;
                try {
                    Console.SetCursorPosition(0, dashBoardLen);
                    Console.WriteFormatted("\tRequests Sent [{0}/{1}] DONE \n\n", Color.Cyan, Color.LightGoldenrodYellow, finished, md5List.Count);
                    Console.WriteFormatted("\t [No] Hash" + blank + "   \tMcGW Detected? \tMcAffee Detected?" + Environment.NewLine,Color.LightGoldenrodYellow);
                    Color backColor;
                    int counter = 0;
                    foreach (var oneResult in tempResults) {
                        backColor = Color.Green;
                        if (oneResult.isCompleted == false || oneResult.resultMc == "NotParsed")
                            backColor = Color.Red;
                        Console.WriteLineFormatted("\t│ [{0}] " + oneResult.DashPrint(), Color.Cyan, backColor, (counter + 1));
                        counter++;
                    }// end of for
                }// end of try
                catch (System.Exception e) {
                    Console.Write("\n\n X│ " + e.Message);
                }
                Console.SetCursorPosition(0, 0);
                Thread.Sleep(900);
            } while (finished != md5List.Count);
        }
        /// <summary>
        /// Prepares mail for SOME
        /// </summary>
        static public void WriteCsirtMail() {
            string attachFile = Directory.GetCurrentDirectory() + "\\results.txt";
            var resultStr = "[No] Hash____________________________    McGW Detected?    McAffee Detected?<br/>" + String.Join("",
                Api.results.Select(ss => ss.MailPrint()));
            //File.ReadAllText(attachFile).Replace("\r\n", "<p></p>").Replace("\t", "&#9;");
            OutlookApp outlookApp = new OutlookApp();
            MailItem mailItem = outlookApp.CreateItem(OlItemType.olMailItem);
            mailItem.Importance = OlImportance.olImportanceHigh;
            mailItem.Subject = "Hash Engellenmesi Hk.";
            // "pre" tag is standing for render as it is dont change anything, thats why we cannot tab on there
            mailItem.HTMLBody =
"<pre " + "style=\"font-family:'consolas'\" >" +
@"Merhaba,<br/>
Aşağıdaki -McAffee Detected?- değeri False ve NotInDB olan <strong>MD5 HASH'lerin engellenmesi</strong> ATAR sistemi üzerinden yapılmıştır.<br/>
Syg.<br/>
" + resultStr + "</pre>";

            mailItem.To = "aa,bb,cc";
            mailItem.CC = "aa,bb,cc";
            if (!File.Exists(attachFile))
                Console.Write("\nAttached document " + attachFile + " does not exist", Color.Red);
            else {
                System.Net.Mail.Attachment attachment = new System.Net.Mail.Attachment(attachFile);
                mailItem.Attachments.Add(attachFile, OlAttachmentType.olByValue, Type.Missing, Type.Missing);
            }
            mailItem.Display();
        }        
        /// <summary>
        /// Prepares mail for ATAR
        /// </summary>
        static public void WriteAtarMail() {
            string attachFile = Directory.GetCurrentDirectory() + "\\results.txt";
            string mailBody = String.Join("", Api.results.Where(ss => 
                (ss.resultMc == "False" || ss.resultMc == "NotInDB") &&
                Regex.IsMatch(ss.md5, "^[0-9a-fA-F]{32}$", RegexOptions.Compiled)).Select(news => news.md5 + "<br/>"));
            OutlookApp outlookApp = new OutlookApp();
            MailItem mailItem = outlookApp.CreateItem(OlItemType.olMailItem);
            mailItem.To = "aa,bb,cc";
            mailItem.CC = "aa,bb,cc";
            mailItem.Subject = "XXX_" + HashChecker.Helpers.userName + "_" + DateTime.Now.ToString("ddMMMMyyyy");
            mailItem.HTMLBody = "<p style=\"font-family:'consolas'\" >" + mailBody + "</p>";
            mailItem.Importance = OlImportance.olImportanceHigh;
            mailItem.Display();
        }
        /// <summary>
        /// 
        /// </summary>
        static public void WriteToFile() {
            File.WriteAllText("results.txt",
                "[No] Hash" + (new string('_', Api.results.First().md5.Length - 4)) + "   \tMcGW Detected? \tMcAffee Detected?" + Environment.NewLine);
            File.AppendAllLines("results.txt", Api.results.Select(ss => ss.ToString()).ToArray());
        }
    }
}// end of namespace