using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace HandleUtils
{
    [Serializable]
    public class SafeWin32Exception : ApplicationException
	{
		int _last_error;
                
        public SafeWin32Exception()
        {
            _last_error = Marshal.GetLastWin32Error();
        }

        public override string Message
        {
            get
            {
                Win32Exception e = new Win32Exception(_last_error);
                return e.Message;
            }
        }        
    }
}
