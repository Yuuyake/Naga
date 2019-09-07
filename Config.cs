using System;
using System.Collections.Generic;

using System.Globalization;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;

namespace Naga
{
    public partial class Config {
        [JsonProperty("proxyAdress")]
        public string proxyAdress { get; set; }

        [JsonProperty("proxyUsername")]
        public string proxyUsername { get; set; }

        [JsonProperty("proxyPassword")]
        public string proxyPassword { get; set; }

        [JsonProperty("csirtMail")]
        public string csirtMail { get; set; }

        [JsonProperty("ksdestekMail")]
        public string ksdestekMail { get; set; }

        [JsonProperty("atarMail")]
        public string atarMail { get; set; }

        [JsonProperty("atarTitle")]
        public string atarTitle { get; set; }

        [JsonProperty("vtApiKeys")]
        public List<VtApiKey> vtApiKeys { get; set; }
    }

    public partial class VtApiKey {
        [JsonProperty("id")]
        public string id { get; set; }

        [JsonProperty("pass")]
        public string pass { get; set; }
    }
}
