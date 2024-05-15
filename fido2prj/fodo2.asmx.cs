using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Web;
using System.Web.Script.Services;
using System.Web.Services;

using Newtonsoft.Json;
using Fido2Net;
using System.IO;

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
            public string challenge;
            public string id;
        }

        public class MakeAssert
        {
            public string username;
        }

        public class MakeAssertionResponse {
            public string credId;
            public string challenge;
            public string credType;
            public string userHandle;
        }

        public class RegisterResp
        {
            public string challenge { get; set; }
            public string userHandle { get; set; }

            public string fmt { get; set; }
            public string sig { get; set; }

            public string authData { get; set; }

            public string clientData { get; set; }
            public string x5c { get; set; }
            public string credentialId { get; set; }
            public string userid { get; set; }
        }


        public class AssertionResp
        {
            public string userid { get; set; }
            public string credentialId { get; set; }
            public string clientData { get; set; }

            public string challenge { get; set; }

            public string userHandle { get; set; }

            public string authenticatorData { get; set; }

            public string sig { get; set; }
        }

        public class RespRequest
        {
            public RespRequest() { }
            public string data { get; set; }
            public string status { get; set; }
        }

        DBOperator dbo = new DBOperator();

        [WebMethod]
        [ScriptMethod(ResponseFormat = ResponseFormat.Json)]
        public void HelloFido2()
        {
            byte[] chanllege = new byte[16];
            RandomNumberGenerator.Create().GetNonZeroBytes(chanllege);

            byte[] id = new byte[32];
            RandomNumberGenerator.Create().GetNonZeroBytes(id);

            // store in database 
            dbo.recordChanllegeDB(id, chanllege);

            RespData data = new RespData { challenge = Base64UrlHelper.EncodeBase64Url( chanllege), id= Base64UrlHelper.EncodeBase64Url(id) };
            Context.Response.Write(JsonConvert.SerializeObject(data));
        }

        [WebMethod]
        [ScriptMethod(ResponseFormat = ResponseFormat.Json)]
        public void HelloFido2Authentication()
        {
            string Data = readPayloadFromRequest(HttpContext.Current.Request);
            var makeAssertionOption = JsonConvert.DeserializeObject<MakeAssert>(Data);

            var credinfo = dbo.getCredentialDB(makeAssertionOption.username);

            byte[] chanllege = new byte[16];
            RandomNumberGenerator.Create().GetNonZeroBytes(chanllege);

            dbo.recordChanllegeDB(Base64UrlHelper.DecodeBase64Url(credinfo.UserHandle), chanllege);

            MakeAssertionResponse data = new MakeAssertionResponse { challenge = Base64UrlHelper.EncodeBase64Url(chanllege), credId = credinfo.CredentialId, credType= credinfo.CredType, userHandle= credinfo.UserHandle };
            Context.Response.Write(JsonConvert.SerializeObject(data));
        }


        [WebMethod]
        [ScriptMethod(ResponseFormat = ResponseFormat.Json)]
        public void VerifyRegistration()
        {
            try
            {
                string Data = readPayloadFromRequest(HttpContext.Current.Request);
                string sPath_App = System.Web.HttpContext.Current.Server.MapPath("~/");
                System.IO.File.WriteAllText(sPath_App + "123.log", Data);

                var registerResp = JsonConvert.DeserializeObject<RegisterResp>(Data);
                var expectedChallenge = dbo.getChallengeFromTemp(registerResp.userHandle);

                bool verify = verifyCred(registerResp, expectedChallenge);

                if (verify)
                {
                    RespRequest resp = new RespRequest { data = expectedChallenge, status = "OK" };


                    Context.Response.Write(JsonConvert.SerializeObject(resp));
                }
                else
                {
                    RespRequest resp = new RespRequest { data = expectedChallenge + ',' + registerResp.challenge + ',' + registerResp.userHandle, status = "ERROR" };
                    Context.Response.Write(JsonConvert.SerializeObject(resp));
                }
            }
            catch(Exception e)
            {

            }
        }

        [WebMethod]
        [ScriptMethod(ResponseFormat = ResponseFormat.Json)]
        public void VerifyAssertion()
        {
            string Data = readPayloadFromRequest(HttpContext.Current.Request);
            string sPath_App = System.Web.HttpContext.Current.Server.MapPath("~/");
            System.IO.File.WriteAllText(sPath_App + "assertion.log", Data);

            var assertionResp = JsonConvert.DeserializeObject<AssertionResp>(Data);
            var expectedChallenge = dbo.getChallengeFromTemp(assertionResp.userHandle);
            var publicKey = dbo.getPublickKey(assertionResp.userid);

            bool verify = verifyAssertionMan(assertionResp, expectedChallenge, publicKey);

            if (verify)
            {
                RespRequest resp = new RespRequest { data = expectedChallenge, status = "OK" };
                Context.Response.Write(JsonConvert.SerializeObject(resp));
            }
            else
            {
                RespRequest resp = new RespRequest { data = expectedChallenge, status = "ERROR" };
                Context.Response.Write(JsonConvert.SerializeObject(resp));
            }
        }


        private string readPayloadFromRequest(HttpRequest request)
        {
            string payload = "";
            using (var stream = new MemoryStream())
            {
                request.InputStream.Seek(0, SeekOrigin.Begin);
                request.InputStream.CopyTo(stream);
                payload = System.Text.Encoding.UTF8.GetString(stream.ToArray());
            }
            return payload;
        } 

        private bool verifyCred(RegisterResp reg, string expectedChallenge) 
        {
            bool ret = false;
            try
            {
                var ext = FidoExtensions.None;
                ReadOnlySpan<byte> authData = Base64UrlHelper.DecodeBase64Url(reg.authData).AsSpan<byte>();
                ReadOnlySpan<byte> x5c = Base64UrlHelper.DecodeBase64Url(reg.x5c).AsSpan<byte>();
                ReadOnlySpan<byte> sig = Base64UrlHelper.DecodeBase64Url(reg.sig).AsSpan<byte>();
                ReadOnlySpan<byte> clientData = Base64UrlHelper.DecodeBase64Url(reg.clientData).AsSpan<byte>();

                using (var cred = new FidoCredential())
                {
                    // ES256 -7
                    cred.SetType(FidoCose.ES256);
                    cred.Rp = new FidoCredentialRp { Name = "local jeffery", Id = "localhost" };
                    cred.SetClientData(clientData);
                    cred.SetAuthDataRaw(authData);
                    cred.SetExtensions(ext);
                    cred.SetX509(x5c);
                    cred.Format = reg.fmt;
                    cred.Signature = sig;
                    cred.Verify();

                    if(expectedChallenge == reg.challenge)
                    {
                        dbo.recordCredentialDB(reg.userid, reg.credentialId, cred.PublicKey.ToArray(), reg.userHandle, cred.SigCounter, cred.AAGUID.ToArray());
                        ret = true;
                    }
                }
            }catch(Exception ex)
            {
            }
            return ret;
        }
        private bool verifyAssertionMan(AssertionResp ast, string expectedChallenge, string publicKey)
        {
            bool ret = false;
            try
            {
                var ext = FidoExtensions.None;
                ReadOnlySpan<byte> clientData = Base64UrlHelper.DecodeBase64Url(ast.clientData).AsSpan<byte>();
                ReadOnlySpan<byte> signature = Base64UrlHelper.DecodeBase64Url(ast.sig).AsSpan<byte>();
                ReadOnlySpan<byte> authenticatorData = Base64UrlHelper.DecodeBase64Url(ast.authenticatorData).AsSpan<byte>();
                ReadOnlySpan<byte> pk = Base64UrlHelper.DecodeBase64Url(publicKey).AsSpan<byte>();
                using (var assert = new FidoAssertion())
                {
                    assert.SetClientData(clientData);
                    assert.Rp = "localhost";
                    assert.Count = 1;
                    assert.SetAuthDataRaw(authenticatorData, 0);
                    assert.SetExtensions(ext);
                    assert.SetSignature(signature, 0);
                    assert.Verify(0, FidoCose.ES256, pk);
                    
                    if(ast.challenge == expectedChallenge)
                    {
                        ret = true;
                    }
                }
            }
            catch(Exception ex)
            {

            }
            return ret;
        }
    }
}
