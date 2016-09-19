using Microsoft.Win32.SafeHandles;
using System;
using System.Runtime.InteropServices;

namespace HandleUtils
{
    public class NativeMappedFile : SafeHandleZeroOrMinusOneIsInvalid
    {
        long _mapsize;

        [DllImport("kernel32.dll", SetLastError=true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool UnmapViewOfFile(IntPtr mapping);

        protected override bool ReleaseHandle()
        {
            return UnmapViewOfFile(handle);
        }        

        public long GetSize()
        {
            return _mapsize;
        }

        public NativeMappedFile(IntPtr h, long mapsize) : base(true)
        {
            SetHandle(h);
            _mapsize = mapsize;
        }

    }
}
