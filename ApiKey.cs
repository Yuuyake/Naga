using System;
using System.Linq;
using System.Text;

namespace HashChecker {
    public class ApiKey {
        public string key;
        public int waitSecs;
        public bool available = true;
        public int index;
        public int usageLeft = 4;
        public ApiKey(string _key, int _secs, bool _available, int _index) {
            key = _key;
            waitSecs = _secs;
            available = _available;
            index = _index;
        }
    }
}
