using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace fido2prj.fido2Lib
{
    public class Base64UrlHelper
    {
        public static string EncodeBase64Url(byte[] data)
        {
            string base64 = Convert.ToBase64String(data);
            string base64Url = base64.Replace('+', '-').Replace('/', '_').TrimEnd('=');
            return base64Url;
        }

        public static byte[] DecodeBase64Url(string base64Url)
        {
            string base64 = base64Url.Replace('-', '+').Replace('_', '/');

            // Pad with '=' characters until length is multiple of 4
            int padding = base64.Length % 4;
            if (padding > 0)
            {
                base64 += new string('=', 4 - padding);
            }

            return Convert.FromBase64String(base64);
        }
    }
}