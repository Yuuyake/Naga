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
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Office.Interop.Outlook;
using OutlookApp = Microsoft.Office.Interop.Outlook.Application;
using Console = Colorful.Console;
using System.Text.RegularExpressions;
using Newtonsoft.Json;
using Naga.Properties;

namespace Naga {
    public class MainClass {
        static public Api vtApi;
        static public Config speconfig;
        static string banner = Resources.banner;
        static string hashFile = "hashes.txt";
        static public List<string> md5List = new List<string>();
        static string header = "[No ] " + "Hash".PadRight(37) + "Rate".PadRight(12) + "McGW Detected?".PadRight(18) + "McAffee Detected?".PadRight(16);

        static void Main(string[] args) {
            Console.OutputEncoding = Encoding.UTF8;
            Console.WriteFormatted(banner, Color.LightGoldenrodYellow);
            try { speconfig = JsonConvert.DeserializeObject<Config>(Resources.speconfig); }
            catch (System.Exception ee) {
                Console.WriteFormatted("\n Config file problem:\n\t" + ee.Message, Color.Red);
                Console.ReadLine();
                return;
            }
            vtApi = new Api();
            vtApi.myProxySetting = Helpers.initializeProxyConfigs();
            Task liveBoard = null;
            try {
                md5List = new List<string>(File.ReadAllLines(hashFile));
                md5List = md5List.Select(s => String.Join("", s.Split(',', '\n', '\t'))).Distinct().ToList(); // clean dirty md5 list
                liveBoard = new Task( () => LiveBoardAsync()); // run the liveboard to see results alive
                liveBoard.Start();
                //vtApi.checkHashes(md5List);
                vtApi.checkHashesNEWAsync(md5List);
                liveBoard.Wait();
                vtApi.results = vtApi.results.OrderBy(ss => ss.resultMc).ToList();
            }
            catch (System.Exception e) {
                Console.WriteLineFormatted("\n | Exception: " + e.Message, Color.Red);
            }
            LiveBoardAsync();//run again to show last results
            //WriteToFile();
            //WriteCsirtMail();
            //WriteAtarMail();
            Console.SetCursorPosition(0, banner.Split('\n').Count() + vtApi.results.Count + 4);
            Console.WriteFormatted("\n__________________________________________  ALL DONE ".PadRight(100,'_'), Color.LightGoldenrodYellow);
            Console.WriteFormatted("\n_".PadRight(100,'_'), Color.LightGoldenrodYellow);
            Console.ReadLine();
            Environment.Exit(0);
        }
        static void LiveBoardAsync() {
            Console.Clear();
            Console.SetCursorPosition(0, 0);
            Console.WriteFormatted(banner, Color.LightGoldenrodYellow);
            int dashBoardLen = banner.Split('\n').Count();
            int finished = 0;
            int cDots = 0;
            do {
                List<Result> tempResults = vtApi.results;
                finished = vtApi.nFinished;
                string waiting = "0";
                try {
                    if (vtApi.timer.IsRunning)
                        waiting = (vtApi.timer.ElapsedMilliseconds / 1000).ToString();
                    Console.SetCursorPosition(0, dashBoardLen + 1);
                    Console.WriteFormatted("\tRequests Sent [{0}/{1}] DONE " + "".PadRight(cDots%5+1,'.').PadRight(6) + "Seconds for new Requests: {2}\n\n",
                        Color.Cyan, Color.LightGoldenrodYellow, finished, md5List.Count,waiting);
                    Console.WriteFormatted("\t  " + header, Color.LightGoldenrodYellow);
                    ResultsToDash(tempResults);
                }// end of try
                catch (System.Exception e) {
                    Console.Write("\n\n X│ " + e.Message);
                }
                Console.SetCursorPosition(0, dashBoardLen + 1);
                Thread.Sleep(1000);
            } while (finished != md5List.Count);
        }
        static public void ResultsToDash(List<Result> tempResults)
        {
            int counter = 0;
            Color backColor;
            foreach (var oneResult in tempResults)
            {
                backColor = Color.Green;
                if (oneResult.isCompleted == false || oneResult.resultMc == "NotParsed")
                    backColor = Color.Red;
                Console.WriteFormatted("\n\t│ [{0}] " + oneResult.DashPrint(), Color.Cyan, backColor, (counter + 1).ToString().PadRight(3));
                counter++;
            }// end of for
        }
        static void WriteCsirtMail() {
            string attachFile = Directory.GetCurrentDirectory() + "\\results.txt";
            var resultStr = header + "<br/>" + String.Join("",vtApi.results.Select(ss => ss.ToString() + "  <br/>"));
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

            mailItem.To = speconfig.csirtMail;
            mailItem.CC = speconfig.ksdestekMail;
            if (!File.Exists(attachFile))
                Console.Write("\nAttached document " + attachFile + " does not exist", Color.Red);
            else {
                System.Net.Mail.Attachment attachment = new System.Net.Mail.Attachment(attachFile);
                mailItem.Attachments.Add(attachFile, OlAttachmentType.olByValue, Type.Missing, Type.Missing);
            }
            mailItem.Display();
        }
        static void WriteAtarMail() {
            string attachFile = Directory.GetCurrentDirectory() + "\\results.txt";
            string mailBody = String.Join("", vtApi.results.Where(ss =>
                (ss.resultMc == "False" || ss.resultMc == "NotInDB") &&
                Regex.IsMatch(ss.md5, "^[0-9a-fA-F]{32}$", RegexOptions.Compiled)).Select(news => news.md5 + "<br/>"));
            OutlookApp outlookApp = new OutlookApp();
            MailItem mailItem = outlookApp.CreateItem(OlItemType.olMailItem);
            mailItem.To = speconfig.atarMail;
            mailItem.CC = speconfig.csirtMail;
            mailItem.Subject = speconfig.atarTitle + Naga.Helpers.userName + "_" + DateTime.Now.ToString("ddMMMMyyyy");
            mailItem.HTMLBody = "<p style=\"font-family:'consolas'\" >" + mailBody + "</p>";
            mailItem.Importance = OlImportance.olImportanceHigh;
            mailItem.Display();
        }
        static void WriteToFile() {
            File.WriteAllText("results.txt", header + Environment.NewLine);
            File.AppendAllLines("results.txt", vtApi.results.Select(ss => ss.ToString()).ToArray());
        }
    }
}// end of namespace