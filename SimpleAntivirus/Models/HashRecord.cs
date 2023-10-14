using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace SimpleAntivirus.Models
{
    public class HashRecord
    {
        public string sha256 { get; set; }
        public string file_name {get ; set; }
        public string file_type { get; set; }
        public string signature { get; set; }
    }
}
