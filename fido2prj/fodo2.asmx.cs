using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Web;
using System.Web.Script.Services;
using System.Web.Services;

using Newtonsoft.Json;

namespace fido2prj
{
    /// <summary>
    ///fodo2 的摘要描述
    /// </summary>
    [WebService(Namespace = "http://tempuri.org/")]
    [WebServiceBinding(ConformsTo = WsiProfiles.BasicProfile1_1)]
    [System.ComponentModel.ToolboxItem(false)]
    // 若要允許使用 ASP.NET AJAX 從指令碼呼叫此 Web 服務，請取消註解下列一行。
    [System.Web.Script.Services.ScriptService]
    public class fodo2 : System.Web.Services.WebService
    {
        public class RespData
        {
            public byte[] challenge;
            public byte[] id;
        }

        [WebMethod]
        [ScriptMethod(ResponseFormat = ResponseFormat.Json)]
        public void HelloFido2()
        {
            byte[] chanllege = new byte[16];
            RandomNumberGenerator.Create().GetNonZeroBytes(chanllege);

            byte[] id = new byte[32];
            RandomNumberGenerator.Create().GetNonZeroBytes(chanllege);

            RespData data = new RespData { challenge = chanllege, id= id };
            Context.Response.Write(JsonConvert.SerializeObject(data));
        }



    }
}
