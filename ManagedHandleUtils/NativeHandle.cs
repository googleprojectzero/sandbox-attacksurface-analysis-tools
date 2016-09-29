using Microsoft.Win32.SafeHandles;
using NtApiDotNet;
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace HandleUtils
{
    public class NativeHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        [DllImport("kernel32.dll", SetLastError=true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool CloseHandle(IntPtr handle);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool DuplicateHandle(IntPtr hSourceProcessHandle, IntPtr hSourceHandle, IntPtr hTargetProcessHandle, out IntPtr lpTargetHandle,
            uint dwDesiredAccess,
            [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle,
            DuplicateObjectOptions dwOptions);

        static IntPtr DupHandle(IntPtr h, uint access_rights, bool same_access)
        {
            IntPtr hDup;

            if (!DuplicateHandle(new IntPtr(-1), h,
                new IntPtr(-1), out hDup, access_rights,
                false, same_access ? DuplicateObjectOptions.SameAccess : DuplicateObjectOptions.None))
            {
                throw new Win32Exception();
            }

            return hDup;
        }

        protected override bool ReleaseHandle()
        {
            return CloseHandle(handle);
        }

        public NativeHandle(IntPtr handle) : this(handle, false)
        {
        }

        public NativeHandle(IntPtr handle, bool duplicate) : base(true)
        {
            SetHandle(duplicate ? DupHandle(handle, 0, true) : handle);
        }

        public NativeHandle Duplicate()
        {
            return new NativeHandle(DupHandle(handle, 0, true));
        }

        public NativeHandle Duplicate(uint access_rights)
        {
            return new NativeHandle(DupHandle(handle, access_rights, false));
        }

        /// <summary>
        /// Returns a kernel object handle.
        /// </summary>
        /// <returns>The kernel object handle. This needs to be disposed after use.</returns>
        internal SafeKernelObjectHandle GetNtApiHandle()
        {
            return new SafeKernelObjectHandle(DupHandle(DangerousGetHandle(), 0, true), true);
        }
    }
}
