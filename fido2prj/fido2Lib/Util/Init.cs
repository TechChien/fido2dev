using fido2prj.Fido2Lib.Interop;
using System;

namespace fido2prj.Fido2Lib.Util
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
            //IntPtr cborHandle = Native.LoadLibrary("cbor.dll");
            //IntPtr crytoHandle = Native.LoadLibrary("crypto-50.dll");
            //IntPtr zlib1Handle = Native.LoadLibrary("zlib1.dll");

            Native.fido_init((int)Fido2Settings.Flags);
        }

        #endregion
    }
}
