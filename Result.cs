using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Naga
{
    public class Result {
        public string order;
        public string md5;
        public string resultMcGw;
        public string resultMc;
        public string overall;
        public string positives;
        public bool isCompleted = false;
        public Result(
            bool isCompleted = false,
            string order = "NULL",
            string md5 = "NULL",
            string resultMcGw = "NULL",
            string resultMc = "NULL",
            string overall = "NULL",
            string positives = "NULL")
        {
            this.overall    = overall;
            this.positives  = positives;
            this.order      = order;
            this.md5        = md5;
            this.resultMcGw = resultMcGw;
            this.resultMc   = resultMc;
            this.isCompleted = isCompleted;
        }
        public override string ToString() {
            return
                " [" + order.PadRight(3) + "] " +
                md5.PadRight(37) + 
                ("[" + positives + "/" + overall + "]").PadRight(12) +
                resultMcGw.PadRight(18) +
                resultMc.PadRight(16);
        }
        public string DashPrint() {
            return
                md5.PadRight(37) +
                ("[" + positives + "/" + overall + "]").PadRight(12) +
                resultMcGw.PadRight(18) +
                resultMc.PadRight(16);
        }
    }
}
