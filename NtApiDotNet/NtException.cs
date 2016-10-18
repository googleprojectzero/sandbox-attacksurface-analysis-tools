using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

namespace NtApiDotNet
{
    [Serializable]
    public sealed class NtException : ApplicationException
    {
        private NtStatus _status;

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr GetModuleHandle(string modulename);

        [Flags]
        enum FormatFlags
        {
            AllocateBuffer = 0x00000100,
            FromHModule = 0x00000800,
            FromSystem = 0x00001000,
            IgnoreInserts = 0x00000200
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern int FormatMessage(
          FormatFlags dwFlags,
          IntPtr lpSource,
          NtStatus dwMessageId,
          int dwLanguageId,
          out SafeLocalAllocHandle lpBuffer,
          int nSize,
          IntPtr Arguments
        );

        public NtException(int status)
        {
            _status = (NtStatus)status;
        }

        public NtException(NtStatus status) 
            : this((int)status)
        {
        }

        public NtStatus Status { get { return _status; } }

        public override string Message
        {
            get
            {
                string message = "Unknown";
                SafeLocalAllocHandle buffer = null;
                if (FormatMessage(FormatFlags.AllocateBuffer | FormatFlags.FromHModule | FormatFlags.FromSystem | FormatFlags.IgnoreInserts,
                    GetModuleHandle("ntdll.dll"), _status, 0, out buffer, 0, IntPtr.Zero) > 0)
                {
                    using (buffer)
                    {
                        message = Marshal.PtrToStringUni(buffer.DangerousGetHandle());
                    }
                }
                else if (Enum.IsDefined(typeof(NtStatus), _status))
                {
                    message = _status.ToString();
                }

                return String.Format("(0x{0:X08}) - {1}", (uint)_status, message);
            }
        }

        public Win32Exception AsWin32Exception()
        {
            return new Win32Exception(NtRtl.RtlNtStatusToDosError(_status));
        }
    }

}
