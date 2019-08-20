using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace HashChecker {
    public class Result {
        public string order;
        public string md5;
        public string resultMcGw;
        public string resultMc;
        public bool isCompleted = false;
        public Result(bool isCompleted, string order, string md5, string resultMcGw, string resultMc) {
            this.order = order;
            this.md5 = md5;
            this.resultMcGw = resultMcGw;
            this.resultMc = resultMc;
            this.isCompleted = isCompleted;
        }
        public override string ToString() {
            return
                " [" + order + "] " +
                md5 + "     \t" +
                resultMcGw + "       \t" +
                resultMc + "               ";
        }
        public string DashPrint() {
            return
                md5 + "     \t" +
                resultMcGw + "       \t" +
                resultMc + "               ";
        }
        public string MailPrint() {
            return " [" + order + "] " + md5 + " &#9;" + resultMcGw + "&#9;&#9;" + resultMc + "  <br/>";
        }
    }
}
