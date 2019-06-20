using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security;
using HashChecker.Properties;
using Console = Colorful.Console;

namespace HashChecker {
    class Helpers {
        /// <summary>
        /// 
        /// </summary>
        /// <returns></returns>
        static public WebProxy initializeProxyConfigs() {
            Console.Write("\n │\n │ Initializing proxy configs...");
            // setting PROXY config and Network CREDENTIALS
            // this is standing here (not in its own function) to get proxy settings
            HttpWebRequest tempReq = (HttpWebRequest)WebRequest.Create("http://google.com");
            WebProxy myProxySetting = new WebProxy();
            if (tempReq.Proxy != null) { // set grabbed proxy settings to myproxy
                Console.Write("\n │\t├─ Proxy: {0}", tempReq.Proxy.GetProxy(tempReq.RequestUri));
                myProxySetting.Address = tempReq.Proxy.GetProxy(tempReq.RequestUri);
            }
            else {
                Console.Write("\n │\t├─ !No proxy detected.\n\t");
                Console.Write("Setting proxy to \"http://mcafeewgf5.int.teb.com.tr:80\"");
                //System.Environment.Exit(1);
                myProxySetting.Address = new Uri("http://mcafeewgf5.int.teb.com.tr:80");
            }
            while (true) {
                // Setting User Creds to pass proxy =============
                string userName = System.Security.Principal.WindowsIdentity.GetCurrent().Name.Split('\\')[1];
                Console.Write("\n │\t├─ Username: ");
                userName = (userName.Length < 3 || userName.Length > 10 || (!userName.Contains("P") && !userName.Contains("p"))) ? "unknown" : userName;
                if (userName == "unknown")
                    userName = Console.ReadLine().Trim('\n', '\t');
                Console.Write(userName);
                SecureString securePwd = new SecureString();
                Console.Write("\n │\t├─ Password: ");
                securePwd = darker(); // ask and save user password on the quiet
                myProxySetting.Credentials = new NetworkCredential(userName, securePwd);
                // ===============================================
                securePwd.Dispose();
                tempReq = (HttpWebRequest)WebRequest.Create("http://google.com");
                tempReq.Proxy = myProxySetting;
                try {
                    using (HttpWebResponse response = (HttpWebResponse)tempReq.GetResponse()) {
                        using (Stream stream = response.GetResponseStream())
                        using (StreamReader reader = new StreamReader(stream))
                            reader.ReadToEnd();
                    }
                    Console.WriteFormatted(" >> Proxy passed ",Color.Green);
                    break;
                }
                catch (Exception e) {
                    if (e.Message.Contains("Proxy Authentication Required")) {
                        Console.WriteFormatted("\n\t│ !!! Incorrect Credentials !!! \n\t│ Press any to try again.", Color.Red);
                        Console.ReadKey();
                        //Environment.Exit(0);
                    }
                    else
                        break;
                }
            }
            return myProxySetting;
        }
        /// <summary>
        /// 
        /// </summary>
        /// <returns></returns>
        static public SecureString darker() { // when writing password to console interface, hides characters
            SecureString securePwd = new SecureString();
            ConsoleKeyInfo key;
            do {
                key = Console.ReadKey(true);
                // Backspace Should Not Work
                if (key.Key != ConsoleKey.Backspace && key.Key != ConsoleKey.Enter) {
                    securePwd.AppendChar(key.KeyChar);
                    Console.Write("*");
                }
                else {
                    if (key.Key == ConsoleKey.Backspace && securePwd.Length > 0) {
                        securePwd = new NetworkCredential("", securePwd.ToString().Substring(0, (securePwd.Length - 1))).SecurePassword;
                        Console.Write("\b \b");
                    }
                    else if (key.Key == ConsoleKey.Enter) {
                        break;
                    }
                }
            } while (true);
            return securePwd;
        }
        /// <summary>
        /// prints live results
        /// </summary>
        /// <param name="results"></param>
        static public void printResults() {

        }
    }
    public class Result {
        public string order ;
        public string md5 ;
        public string resultMcGw ;
        public string resultMc ;
        public bool isCompleted = false;
        public Result(bool isCompleted,string order,string md5,string resultMcGw,string resultMc) {
            this.order = order;
            this.md5 = md5;
            this.resultMcGw = resultMcGw;
            this.resultMc = resultMc;
            this.isCompleted = isCompleted;
        }
        public override string ToString() {
            return 
                "\t│ [" + order + "] " +
                md5 + "   \t" +
                resultMcGw + "       \t" +
                resultMc + "               ";
        }
    }
}
