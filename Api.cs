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
        public List<ApiKey> apiKeys;
        public List<Result> results;
        public List<Task> allTasks; // list of async task that will do the API calls
        public Random random;
        public SemaphoreSlim myLocker;
        public Stopwatch timer;
        public int nFinished;
        public string status;
        public string apiURL;
        public WebProxy myProxySetting;
        public ApiKey GetaKey() {
            myLocker.Wait();
            try {
                while (true) {
                    ApiKey tempKey = apiKeys.FirstOrDefault(key => key.usageLeft > 0);
                    if (tempKey == null) {
                        status = "KeyLimit";
                        Thread.Sleep(random.Next(40000, 50000));
                        apiKeys.ForEach(kk => kk.usageLeft = 4);// api key limit is 4
                        status = "NewSession";
                    }
                    else {
                        apiKeys[tempKey.index].usageLeft -= 1;
                        return tempKey;
                    }
                }//end of while
            }
            finally {
                myLocker.Release();
            }
        }
        public Api() {
            apiKeys  = new List<ApiKey>();
            results  = new List<Result>();
            allTasks = new List<Task>();
            random   = new Random();
            myLocker = new SemaphoreSlim(1, 1);
            status   = "initial";
            apiURL   = "https://www.virustotal.com/vtapi/v2/file/report?apikey=";
            nFinished = 0;
            SetKeys();
        }
        /// <summary>
        /// an Async methot to get all VirusTotal results of given MD5 list in aspect of McAfee and McAfee-Gw
        /// </summary>
        /// <param name="listMD5"></param>
        /// <returns></returns>
        public void checkHashes(List<string> listMD5) {
            foreach (int cnt in Enumerable.Range(0, listMD5.Count))
                results.Add(new Result(false, cnt.ToString(), listMD5[cnt], "Getting...", "Getting...", "NA", "NA"));

            for (int i = 0; i < listMD5.Count; i++) {
                int counter = i; // counter to pass parametre to "checkOneMD5" function
                allTasks.Add(new Task(() => results[counter] = checkOneHash(listMD5[counter], counter))); // async version
                allTasks[i].Start();
                //results[counter] = checkOneHash(listMD5[counter], counter); // sync version
                Thread.Sleep(200);
            }
        }
        public void checkHashesNEW(List<string> listMD5) {
            foreach (int cnt in Enumerable.Range(0, listMD5.Count))
                results.Add(new Result(false, cnt.ToString(), listMD5[cnt], "Getting...", "Getting...", "NA", "NA"));

            int maxParallel = 30;
            for (int i = 0; i < listMD5.Count; i++) {
                // counter to pass parametre to "checkOneMD5" function
                // bc of async function takes long to start, "i" will change before it and this have to be prevented
                int counter = i;
                allTasks.Add(new Task(() => results[counter] = checkOneHash(listMD5[counter], counter)));
                allTasks[counter].Start();
                if (allTasks.Count == maxParallel) {
                    int idx = Task.WaitAny(allTasks.ToArray());
                    allTasks.RemoveAt(idx);
                }
                //results[counter] = checkOneMD5(listMD5[counter]);
                Thread.Sleep(200);
            }
        }
        /// <summary>
        /// methot to get a VirusTotal result of given MD5 in aspect of McAfee and McAfee-Gw
        /// </summary>
        /// <param name="md5"></param>
        /// <param name="callNumber"></param>
        /// <returns>string</returns>
        public Result checkOneHash(string hash, int counter) {
            Result tempResult = new Result(false, counter.ToString(), "MD5EquivalentNotFetched", "NotFetched", "NotFetched", "NA", "NA");
            ApiKey currApiKey;
            while (true) {
                currApiKey = GetaKey(); // get an API key for request
                try {   // create request , read response
                    string resultRaw = MakeOneRequest(currApiKey, hash);
                    if (resultRaw == "KeyLimit")
                        continue;
                    dynamic resultJson = JsonConvert.DeserializeObject(resultRaw);
                    try   { tempResult.md5 = resultJson.md5 ?? hash; } 
                    catch { tempResult.md5 = hash; }
                    if (resultJson.response_code == "0") {
                        tempResult.resultMc = "NotInDB";
                        tempResult.resultMcGw = "NotInDB";
                    }
                    else {
                        try   { tempResult.positives  = resultJson.positives; }
                        catch { tempResult.positives  = "NotParsed"; }
                        try   { tempResult.overall    = resultJson.total; }
                        catch { tempResult.overall    = "NotParsed"; }
                        try   { tempResult.resultMc   = resultJson.scans.McAfee.detected; }
                        catch { tempResult.resultMc   = "NotParsed"; }
                        try   { tempResult.resultMcGw = resultJson.scans["McAfee-GW-Edition"].detected; }
                        catch { tempResult.resultMcGw = "NotParsed"; }
                    }
                }
                catch (System.Exception e) {
                    if (e.Message.Contains("403"))
                        Console.WriteFormatted("\n │ " + e.Message, Color.Red);
                    tempResult.resultMc = "Unknown";
                    tempResult.resultMc = "Unknown";
                }
                tempResult.isCompleted = true;
                nFinished++;
                return tempResult;
            }// while (true)
        }// checkMD5s(string MD5)
        /// <summary>
        /// 
        /// </summary>
        /// <returns></returns>
        public string MakeOneRequest(ApiKey currApiKey, string hash) {
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
        public void SetKeys() {
            int counter = 0;
            var strkeys = MainClass.speconfig.vtApiKeys;
            strkeys.ForEach(kk => apiKeys.Add(new ApiKey(kk.id,kk.pass, 0, true, counter++)));
            counter = 0;
        }
    }//end of Class
}
