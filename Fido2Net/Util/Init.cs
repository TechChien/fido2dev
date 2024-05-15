using Fido2Net.Interop;
using System;
using System.IO;
using System.Web;

namespace Fido2Net.Util
{
    internal static class Init
    {
        #region Variables

        private static bool _called;

        #endregion

        #region Public Methods

        public static void Call()
        {
            if (_called) {
                return;
            }
            
            _called = true;
            string originalDirectory = Directory.GetCurrentDirectory();

            try
            {
                string dllDirectory = HttpContext.Current.Server.MapPath("~/bin");
                //string dllDirectory = @"C:\Users\roger.chien\Project\fido2dev\fido2prj\bin";
                Directory.SetCurrentDirectory(dllDirectory);

                IntPtr cborHandle = Native.LoadLibrary("cbor.dll");
                IntPtr crytoHandle = Native.LoadLibrary("crypto-50.dll");
                IntPtr zlib1Handle = Native.LoadLibrary("zlib1.dll");
            }
            catch (Exception e)
            {

            }
            finally
            {
                Directory.SetCurrentDirectory(originalDirectory);
            }

            Native.fido_init((int)Fido2Settings.Flags);
        }

        #endregion
    }
}
