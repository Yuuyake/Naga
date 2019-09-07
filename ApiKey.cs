using System;
using System.Linq;
using System.Text;

namespace Naga
{
    public class ApiKey {
        public string name;
        public string key;
        public int lastUsage;
        public bool available;
        public int index;
        public int usageLeft;
        public ApiKey(string _name, string _key, int _secs, bool _available, int _index) {
            name        = _name;
            key         = _key;
            lastUsage   = _secs;
            available   = _available;
            index       = _index;
            usageLeft   = 4;
        }
    }
}
