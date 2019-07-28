/*
│ Emre Ekinci                                     
│ yunusemrem@windowslive.com	                   
│ 05550453800                                       
│                                      
│        
│      TODO:
                > Listeyi değişiklik olunca yenile
	            > listenin sadece değişikliklerini yenile		
	            > API lere kalan zaman değeri ver
                > response result ları bir class ta tut
*/
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using HashChecker.Properties;
using Newtonsoft.Json;
using Microsoft.Office.Interop.Outlook;
using OutlookApp = Microsoft.Office.Interop.Outlook.Application;
using Console = Colorful.Console;
using System.Text.RegularExpressions;

namespace HashChecker {
    public class MainClass {
        static string banner                = Resources.banner;
        static string hashFile              = "hashes.txt";
        static string apiURL                = "https://www.virustotal.com/vtapi/v2/file/report?apikey=";
        static public WebProxy myProxySetting;
        static public Random random         = new Random();
        static public API virusTotalAPI     = new API();
        static public List<Result> results  = new List<Result>();
        static public List<Task> allTasks   = new List<Task>(); // list of async task that will do the API calls

        static void Main(string[] args) {
            Console.OutputEncoding = Encoding.UTF8;
            Console.WriteFormatted(banner, Color.LightGoldenrodYellow);
            myProxySetting = Helpers.initializeProxyConfigs();
            Task liveBoard = null;
            try {
                List<string> md5List = new List<string>(File.ReadAllLines(hashFile));
                md5List = md5List.Select(s => String.Join("", s.Split(',', '\n', '\t'))).Distinct().ToList(); // clean dirty md5 list
                liveBoard = Task.Factory.StartNew(() => LiveBoard()); // run the liveboard to see results alive
                checkMD5s(md5List);
            }
            catch (System.Exception e) {
                Console.WriteLineFormatted("\n | " + e.Message,Color.Red);
            }
            liveBoard.Wait();
            results = results.OrderBy(ss => ss.resultMc).ToList();
            LiveBoard();
            File.WriteAllText("results.txt",
                "[No] Hash" + (new string('_',results.First().md5.Length-4)) + "   \tMcGW Detected? \tMcAffee Detected?" + Environment.NewLine);
            File.AppendAllLines("results.txt", results.Select(ss => ss.ToString()).ToArray());
            WriteSomeMail();
            WriteAtarMail();
            Console.SetCursorPosition(0, banner.Split('\n').ToList().Count + results.Count + 3 );
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
            List<Result> tempResults = null;
            do {
                tempResults = results;
                try {
                    Console.SetCursorPosition(0, dashBoardLen);
                    Console.WriteFormatted("\tRequests Sent [{0}/{1}] DONE \n\n", Color.Cyan, Color.LightGoldenrodYellow,
                    tempResults.Count(ss => ss.isCompleted == true), tempResults.Count());
                    Console.WriteFormatted("\t [No] Hash" + blank + "   \tMcGW Detected? \tMcAffee Detected?" + Environment.NewLine,Color.LightGoldenrodYellow);
                    Color focusColor;
                    Color backColor;
                    int counter = 0;
                    foreach (var oneResult in tempResults.ToList()) {
                        focusColor = Color.Cyan;
                        backColor = Color.Green;
                        if (oneResult.isCompleted == false || oneResult.resultMc == "NotParsed") {
                            focusColor = Color.Red;
                            backColor = Color.Red;
                        }
                        Console.WriteLineFormatted(
                            "\t│ [{0}] " +
                            oneResult.md5 + "   \t" +
                            oneResult.resultMcGw + "      \t" +
                            oneResult.resultMc + "               ", focusColor, backColor, (counter + 1));
                        counter++;
                    }// end of for
                }// end of try
                catch (System.Exception e) {
                    Console.Write("\n\n X│ " + e.Message);
                }
                Console.SetCursorPosition(0, 0);
                Thread.Sleep(1000);
            } while (tempResults.Count(ss=> ss.isCompleted == false) != 0 );
        }
        /// <summary>
        /// an Async methot to get all VirusTotal results of given MD5 list in aspect of McAfee and McAfee-Gw
        /// </summary>
        /// <param name="listMD5"></param>
        /// <returns></returns>
        static void checkMD5s(List<string> listMD5) {
            HttpClientHandler myHttpHandler = new HttpClientHandler();
            myHttpHandler.AllowAutoRedirect = false;
            HttpClient myClient = new HttpClient(myHttpHandler);
            foreach (int cnt in Enumerable.Range(0, listMD5.Count))
                results.Add(new Result(false, cnt.ToString(), listMD5[cnt], "Getting...", "Getting..."));

            for (int i = 0; i < listMD5.Count; i++) {
                int counter = i; // counter to pass parametre to "checkOneMD5" function
                allTasks.Add(new Task(() => results[counter] = checkOneHash(listMD5[counter], counter)));
                allTasks[i].Start();
                //results[counter] = checkOneMD5(listMD5[counter]);
                Thread.Sleep(random.Next(100, 200));
            }
        }
        /// <summary>
        /// methot to get a VirusTotal result of given MD5 in aspect of McAfee and McAfee-Gw
        /// </summary>
        /// <param name="md5"></param>
        /// <param name="callNumber"></param>
        /// <returns>string</returns>
        static public Result checkOneHash(string hash,int counter) {
            string fromMc       = "NotFetched";
            string fromMcGW     = "NotFetched";
            string md5_result   = "MD5EquivalentNotFetched";
            APIKEY currApiKey;
            while (true) {
                currApiKey = virusTotalAPI.GetKey(); // set the API key
                string resutlRaw = "";
                try {   // create request , read response
                    //Console.WriteFormatted("\n ├─{0} Requesting result: [{1}]", Color.Cyan, Color.FromArgb(0, 255, 0), "-{APIKEY " + currApiKey.index + "}", md5);
                    HttpWebRequest requestAPI = (HttpWebRequest)WebRequest.Create(apiURL + currApiKey.key + "&resource=" + hash);
                    requestAPI.Proxy = myProxySetting;
                    using (HttpWebResponse response = (HttpWebResponse)requestAPI.GetResponse()) {
                        if (response.Headers.ToString().Contains("You have reached your API quota limits") == true) {
                            virusTotalAPI.apiKeys[currApiKey.index].usageLeft = 0;
                            continue;
                        }
                        using (Stream stream = response.GetResponseStream())
                        using (StreamReader reader = new StreamReader(stream))
                            resutlRaw = reader.ReadToEnd();
                    }
                    dynamic resultJson = JsonConvert.DeserializeObject(resutlRaw);
                    if(resultJson.response_code == "0")
                        return new Result(true, counter.ToString(), hash, "NotInDB" ,"NotInDB");
                    try { md5_result = resultJson.md5; }
                    catch { md5_result = "SHA_" + hash; }
                    try { fromMc = resultJson.scans.McAfee.detected; }
                    catch { fromMc = "NotParsed"; }
                    try { fromMcGW = resultJson.scans["McAfee-GW-Edition"].detected; }
                    catch { fromMcGW = "NotParsed"; }
                }
                catch (System.Exception e) {
                    if (e.Message.Contains("403"))
                        Console.WriteFormatted("\n │ " + e.Message, Color.Red);
                    fromMc = "Unknown";
                    fromMcGW = "Unknown";
                }
                //Console.WriteFormatted("\n\n\t│" + result, Color.White);
                return new Result(true, counter.ToString(), md5_result, fromMcGW, fromMc); 
            }// while (true)
        }// checkMD5s(string MD5)
        /// <summary>
        /// Prepares mail for SOME
        /// </summary>
        static public void WriteSomeMail() {
            string attachFile = Directory.GetCurrentDirectory() + "\\results.txt";
            var resultStr = "[No] Hash____________________________    McGW Detected?    McAffee Detected?<br/>" + String.Join("",
                results.Select(ss => " [" + ss.order + "] " + ss.md5 + " &#9;" + ss.resultMcGw + "&#9;&#9;" + ss.resultMc + "  <br/>"));
            //File.ReadAllText(attachFile).Replace("\r\n", "<p></p>").Replace("\t", "&#9;");
            OutlookApp outlookApp = new OutlookApp();
            MailItem mailItem = outlookApp.CreateItem(OlItemType.olMailItem);
            mailItem.Importance = OlImportance.olImportanceHigh;
            mailItem.Subject = "Hash Engellenmesi Hk.";
            // "pre" tag is standing for render as it is dont change anything, thats why we cannot tab on there
            mailItem.HTMLBody =
"<pre " + "style=\"font-family:'consolas'\" >" +
@"Merhaba,<br/>
Aşağıdaki -McAffee Detected?- değeri False ve NotInDB olan <strong>MD5 HASH'lerin engellenmesi</strong> XXX sistemi üzerinden yapılmıştır.<br/>
Syg.<br/>
" + resultStr + "</pre>";

            mailItem.To = "TO LIST WITH comma";
            mailItem.CC = "CC LIST WITH comma";
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
            string mailBody = String.Join("", results.Where(ss => 
                (ss.resultMc == "False" || ss.resultMc == "NotInDB") &&
                Regex.IsMatch(ss.md5, "^[0-9a-fA-F]{32}$", RegexOptions.Compiled)).Select(news => news.md5 + "<br/>"));
            OutlookApp outlookApp = new OutlookApp();
            MailItem mailItem = outlookApp.CreateItem(OlItemType.olMailItem);
            mailItem.To = "PUT ATAR MAIL HERE";
            mailItem.CC = "CC LIST WITH comma";
            mailItem.Subject = "INT_" + HashChecker.Helpers.userName + "_" + DateTime.Now.ToString("ddMMMMyyyy");
            mailItem.HTMLBody = "<p style=\"font-family:'consolas'\" >" + mailBody + "</p>";
            mailItem.Importance = OlImportance.olImportanceHigh;
            mailItem.Display();
        }
        /// <summary>
        /// 
        /// </summary>
        public class APIKEY {
            public string key;
            public int waitSecs;
            public bool available = true;
            public int index;
            public int usageLeft = 4;
            public APIKEY(string _key, int _secs, bool _available, int _index) {
                key       = _key;
                waitSecs  = _secs;
                available = _available;
                index     = _index;
            }
        }
        /// <summary>
        /// 
        /// </summary>
        public class API {
            public List<APIKEY> apiKeys = new List<APIKEY>();
            public Stopwatch timer;
            public bool limitReached = false;
            static SemaphoreSlim myLocker = new SemaphoreSlim(1, 1);
            public API() { SetKeys(); }
            public APIKEY GetKey() {
                myLocker.Wait();
                try {
                    while (true) {
                        APIKEY tempKey = apiKeys.FirstOrDefault(key => key.usageLeft > 0);
                        if (tempKey == null) {
                            Thread.Sleep(random.Next(40000, 50000));
                            foreach (APIKEY kk in apiKeys)
                                kk.usageLeft = 4; // api key limit is 4
                        }
                        else {
                            apiKeys[tempKey.index].usageLeft = apiKeys[tempKey.index].usageLeft <= 0 ? 0 : apiKeys[tempKey.index].usageLeft-1;
                            return tempKey;
                        }
                    }//end of while
                }
                finally {
                    myLocker.Release();
                }
            }
            public void SetKeys() {
                int counter = 0;
                apiKeys = new List<APIKEY> { // fill VT API keys here, except one belows are encrypted by me, will not work you can try to decrypt
                    new APIKEY("4b17dea20e1caa790f045dcb5b3063a15428f8fe4a00d907fa5e9d70f8dee258",0,true,counter++),
                    /*
                    new APIKEY("1b4f6a9193534b8e053bc19a717ec3023aaba49e2a2089ee2c9a6b74a658b16b",0,true,counter++),
                    new APIKEY("fa1fb758f4c36edc14b86e73d4d5317b90b26b7aed9963e8c854175e86fe6301",0,true,counter++),
                    new APIKEY("5aafbe5c1a2cee8f80bf698823732705ab34378f5d5764ce1d02c20660243a07",0,true,counter++),
                    new APIKEY("70d6f9b87978684be2fce948d5fd8627834b841d3c2bd73eb6ec456a16b6928a",0,true,counter++),
                    new APIKEY("233ceeca97c6ebb6f1671343d06aa5d48b018ba1ceb2b27645010bf14d5f7d6e",0,true,counter++),
                    new APIKEY("c9bbd216aa7844cf8aa3fbecd7f41b6bab0892f91a82514b10b5cbcdb8bc8d78",0,true,counter++),
                    new APIKEY("d19bd32847fd913f0ad26f6da1a648a9e4ac37314aba1573ba07dafaad08838e",0,true,counter++),
                    new APIKEY("139c8e01faf7064e4e25572024f0afd773c182f6e39cc4ac74bccaa3e3e29353",0,true,counter++),
                    new APIKEY("ec03b36147eef77626322e734287b02b077280544aeca5956f91524eaf16e9d4",0,true,counter++),
                    new APIKEY("abb454e756e8d071c0b8d0eb0b7f6bcaaaa78bb4543dfc42d153b318cc7e044f",0,true,counter++),
                    new APIKEY("fc75052b6a74e80adbb4c7b489abfc778087357e92839a19f57f39a645d8e87e",0,true,counter++),
                    new APIKEY("eb212c4ddc0b48b0fd9518fc9e5cc76044f270ff7ebf1953431b979cd4e668cb",0,true,counter++),
                    new APIKEY("9bd19ed4124d53d3d11c0b7d15fb5eda096a6a76c1a41b4f305284da4da899d1",0,true,counter++),
                    new APIKEY("7300c3da7fce522819e45e6bab0259c757f2987a50d8de6b2aae18561840b06e",0,true,counter++),
                    */
                };
            }
        }
    }//end of Class
}// end of namespace