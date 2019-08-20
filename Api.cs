using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Newtonsoft.Json;
using Console = Colorful.Console;
using System.Diagnostics;

namespace HashChecker {
    public class Api {
        static public List<ApiKey> apiKeys   = new List<ApiKey>();
        static public List<Result> results   = new List<Result>();
        static public List<Task> allTasks    = new List<Task>(); // list of async task that will do the API calls
        static public Random random          = new Random();
        static public SemaphoreSlim myLocker = new SemaphoreSlim(1, 1);
        static public bool limitReached      = false;
        static public string apiURL = "https://www.virustotal.com/vtapi/v2/file/report?apikey=";
        public WebProxy myProxySetting;

        static public Stopwatch timer;
        static public ApiKey GetaKey() {
            myLocker.Wait();
            try {
                while (true) {
                    ApiKey tempKey = apiKeys.FirstOrDefault(key => key.usageLeft > 0);
                    if (tempKey == null) {
                        Thread.Sleep(random.Next(40000, 50000));
                        apiKeys.ForEach(kk => kk.usageLeft = 4);// api key limit is 4
                    }
                    else {
                        apiKeys[tempKey.index].usageLeft = tempKey.usageLeft - 1;
                        return tempKey;
                    }
                }//end of while
            }
            finally {
                myLocker.Release();
            }
        }
        static public void SetKeys() {
            int counter = 0;
            apiKeys = new List<ApiKey> {
                    new ApiKey("4b17dea20e1caa790f045dcb5b3063a15428f8fe4a00d907fa5e9d70f8dee258",0,true,counter++),
                    new ApiKey("bb4f6a9193534b8e053bc19a717ec3023aaba49e2a2089ee2c9a6b74a658b161",0,true,counter++),
                    new ApiKey("1a1fb758f4c36edc14b86e73d4d5317b90b26b7aed9963e8c854175e86fe630f",0,true,counter++),
                    new ApiKey("7aafbe5c1a2cee8f80bf698823732705ab34378f5d5764ce1d02c20660243a05",0,true,counter++),
                    new ApiKey("a0d6f9b87978684be2fce948d5fd8627834b841d3c2bd73eb6ec456a16b69287",0,true,counter++),
                    new ApiKey("233ceeca97c6ebb6f1671343d06aa5d48b018ba1ceb2b27645010bf14d5f7d6e",0,true,counter++),
                    new ApiKey("89bbd216aa7844cf8aa3fbecd7f41b6bab0892f91a82514b10b5cbcdb8bc8d7c",0,true,counter++),
                    new ApiKey("e19bd32847fd913f0ad26f6da1a648a9e4ac37314aba1573ba07dafaad08838d",0,true,counter++),
                    new ApiKey("339c8e01faf7064e4e25572024f0afd773c182f6e39cc4ac74bccaa3e3e29351",0,true,counter++),
                    new ApiKey("4c03b36147eef77626322e734287b02b077280544aeca5956f91524eaf16e9de",0,true,counter++),
                    new ApiKey("fbb454e756e8d071c0b8d0eb0b7f6bcaaaa78bb4543dfc42d153b318cc7e044a",0,true,counter++),
                    new ApiKey("ec75052b6a74e80adbb4c7b489abfc778087357e92839a19f57f39a645d8e87f",0,true,counter++),
                    new ApiKey("bb212c4ddc0b48b0fd9518fc9e5cc76044f270ff7ebf1953431b979cd4e668ce",0,true,counter++),
                    new ApiKey("1bd19ed4124d53d3d11c0b7d15fb5eda096a6a76c1a41b4f305284da4da899d9",0,true,counter++),
                    new ApiKey("e300c3da7fce522819e45e6bab0259c757f2987a50d8de6b2aae18561840b067",0,true,counter++),/**/
                };
        }
        /// <summary>
        /// an Async methot to get all VirusTotal results of given MD5 list in aspect of McAfee and McAfee-Gw
        /// </summary>
        /// <param name="listMD5"></param>
        /// <returns></returns>
        public void checkHashes(List<string> listMD5) {
            foreach (int cnt in Enumerable.Range(0, listMD5.Count))
                results.Add(new Result(false, cnt.ToString(), listMD5[cnt], "Getting...", "Getting..."));

            for (int i = 0; i < listMD5.Count; i++) {
                int counter = i; // counter to pass parametre to "checkOneMD5" function
                allTasks.Add(new Task(() => results[counter] = checkOneHash(listMD5[counter], counter)));
                allTasks[i].Start();
                //results[counter] = checkOneMD5(listMD5[counter]);
                Thread.Sleep(200);
            }
        }
        public void BIG(List<string> listMD5) {
            foreach (int cnt in Enumerable.Range(0, listMD5.Count))
                results.Add(new Result(false, cnt.ToString(), listMD5[cnt], "Getting...", "Getting..."));

            while (true) {
                for (int i = 0; i < apiKeys.Count; i++) {
                    // counter to pass parametre to "checkOneMD5" function
                    // bc of async function takes long to start, "i" will change before it and this have to be prevented
                    int counter = i;
                    allTasks.Add(new Task(() => results[counter] = checkOneHash(listMD5[counter], counter)));
                    allTasks[counter].Start();
                    //results[counter] = checkOneMD5(listMD5[counter]);
                    Thread.Sleep(200);
                }

                Task.WaitAny(allTasks.ToArray());
            }


        }
        /// <summary>
        /// methot to get a VirusTotal result of given MD5 in aspect of McAfee and McAfee-Gw
        /// </summary>
        /// <param name="md5"></param>
        /// <param name="callNumber"></param>
        /// <returns>string</returns>
        public Result checkOneHash(string hash, int counter) {
            Result tempResult = new Result(false, counter.ToString(), "MD5EquivalentNotFetched", "NotFetched", "NotFetched"); 
            ApiKey currApiKey;
            while (true) {
                currApiKey = GetaKey(); // get an API key for request
                try {   // create request , read response
                    string resultRaw = MakeOneRequest(currApiKey,hash);
                    if (resultRaw == "KeyLimit")
                        continue;
                    dynamic resultJson = JsonConvert.DeserializeObject(resultRaw);

                    if (resultJson.response_code == "0") {
                        tempResult.resultMc   = "NotInDB";
                        tempResult.resultMcGw = "NotInDB";
                        tempResult.isCompleted = true;
                    }
                    try { tempResult.md5 = resultJson.md5; }
                    catch { tempResult.md5 = "SHA_" + hash; }
                    try { tempResult.resultMc = resultJson.scans.McAfee.detected; }
                    catch { tempResult.resultMc = "NotParsed"; }
                    try { tempResult.resultMcGw = resultJson.scans["McAfee-GW-Edition"].detected; }
                    catch { tempResult.resultMcGw = "NotParsed"; }
                }
                catch (System.Exception e) {
                    if (e.Message.Contains("403"))
                        Console.WriteFormatted("\n │ " + e.Message, Color.Red);
                    tempResult.resultMc = "Unknown";
                    tempResult.resultMc = "Unknown";
                }
                tempResult.isCompleted = true;
                return tempResult;
            }// while (true)
        }// checkMD5s(string MD5)
        /// <summary>
        /// 
        /// </summary>
        /// <returns></returns>
        public string MakeOneRequest(ApiKey currApiKey,string hash) {
            string resultRaw = "NoResultFetched";
            //Console.WriteFormatted("\n ├─{0} Requesting result: [{1}]", Color.Cyan, Color.FromArgb(0, 255, 0), "-{APIKEY " + currApiKey.index + "}", md5);
            HttpWebRequest requestAPI = (HttpWebRequest)WebRequest.Create(apiURL + currApiKey.key + "&resource=" + hash);
            requestAPI.Proxy = myProxySetting;
            using (HttpWebResponse response = (HttpWebResponse)requestAPI.GetResponse()) {
                if (response.Headers.ToString().Contains("You have reached your API quota limits") == true) {
                    apiKeys[currApiKey.index].usageLeft = 0;
                    return "KeyLimit";
                }
                using (Stream stream = response.GetResponseStream())
                using (StreamReader reader = new StreamReader(stream))
                    resultRaw = reader.ReadToEnd();
            }
            return resultRaw;
        }
    }//end of Class
}
