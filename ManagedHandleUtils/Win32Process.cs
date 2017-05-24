//  Copyright 2016 Google Inc. All Rights Reserved.
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//  http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

using NtApiDotNet;
using System;
using System.Runtime.InteropServices;

namespace SandboxAnalysisUtils
{
    [Flags]
    public enum CreateProcessFlags
    {
        None = 0,
        CREATE_BREAKAWAY_FROM_JOB = 0x01000000,
        CREATE_DEFAULT_ERROR_MODE = 0x04000000,
        CREATE_NEW_CONSOLE = 0x00000010,
        CREATE_NEW_PROCESS_GROUP = 0x00000200,
        CREATE_NO_WINDOW = 0x08000000,
        CREATE_PROTECTED_PROCESS = 0x00040000,
        CREATE_PRESERVE_CODE_AUTHZ_LEVEL = 0x02000000,
        CREATE_SEPARATE_WOW_VDM = 0x00000800,
        CREATE_SHARED_WOW_VDM = 0x00001000,
        CREATE_SUSPENDED = 0x00000004,
        CREATE_UNICODE_ENVIRONMENT = 0x00000400,
        DEBUG_ONLY_THIS_PROCESS = 0x00000002,
        DEBUG_PROCESS = 0x00000001,
        DETACHED_PROCESS = 0x00000008,
        EXTENDED_STARTUPINFO_PRESENT = 0x00080000,
        INHERIT_PARENT_AFFINITY = 0x00010000
    }

    [Flags]
    public enum CreateProcessLogonFlags
    {
        None = 0,
        WithProfile = 1,
        NetCredentialsOnly = 2,
    }

    public sealed class Win32Process : IDisposable
    {
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct STARTUPINFO
        {
            public Int32 cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public Int32 dwX;
            public Int32 dwY;
            public Int32 dwXSize;
            public Int32 dwYSize;
            public Int32 dwXCountChars;
            public Int32 dwYCountChars;
            public Int32 dwFillAttribute;
            public Int32 dwFlags;
            public Int16 wShowWindow;
            public Int16 cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
        class STARTUPINFOEX
        {
            public STARTUPINFO StartupInfo;
            public IntPtr lpAttributeList;

            public STARTUPINFOEX()
            {
                StartupInfo.cb = Marshal.SizeOf(this);
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        class SafeProcThreadAttributeListBuffer : SafeHGlobalBuffer
        {
            [DllImport("kernel32.dll", SetLastError = true)]
            static extern bool InitializeProcThreadAttributeList(
                IntPtr lpAttributeList,
                int dwAttributeCount,
                int dwFlags,
                ref IntPtr lpSize
            );

            [DllImport("kernel32.dll", SetLastError = true)]
            static extern bool UpdateProcThreadAttribute(
                IntPtr lpAttributeList,
                int dwFlags,
                IntPtr Attribute,
                IntPtr lpValue,
                IntPtr cbSize,
                IntPtr lpPreviousValue,
                IntPtr lpReturnSize
            );

            [DllImport("kernel32.dll", SetLastError = true)]
            static extern bool DeleteProcThreadAttributeList(
                IntPtr lpAttributeList
            );

            private static int GetAttributeListSize(int count)
            {
                IntPtr size = IntPtr.Zero;
                InitializeProcThreadAttributeList(IntPtr.Zero, count, 0, ref size);
                return size.ToInt32();
            }

            public SafeProcThreadAttributeListBuffer(int count) : base(GetAttributeListSize(count))
            {
                IntPtr size = new IntPtr(Length);
                if (!InitializeProcThreadAttributeList(handle, count, 0, ref size))
                {
                    throw new SafeWin32Exception();
                }
            }

            public void AddAttribute(IntPtr attribute, SafeHGlobalBuffer value)
            {
                if (!UpdateProcThreadAttribute(handle, 0, attribute, value.DangerousGetHandle(), new IntPtr(value.Length), IntPtr.Zero, IntPtr.Zero))
                {
                    throw new SafeWin32Exception();
                }
            }

            protected override bool ReleaseHandle()
            {
                if (!IsInvalid)
                {
                    bool ret = DeleteProcThreadAttributeList(handle);
                    return base.ReleaseHandle() && ret;
                }
                return false;
            }
        }

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern bool CreateProcessAsUser(
          SafeKernelObjectHandle hToken,
          string lpApplicationName,
          string lpCommandLine,
          IntPtr lpProcessAttributes,
          IntPtr lpThreadAttributes,
          bool bInheritHandles,
          CreateProcessFlags dwCreationFlags,
          IntPtr lpEnvironment,
          string lpCurrentDirectory,
          ref STARTUPINFO lpStartupInfo,
          out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern bool CreateProcessWithTokenW(
          SafeKernelObjectHandle hToken,
          CreateProcessLogonFlags dwLogonFlags,
          string lpApplicationName,
          string lpCommandLine,
          CreateProcessFlags dwCreationFlags,
          IntPtr lpEnvironment,
          string lpCurrentDirectory,
          ref STARTUPINFO lpStartupInfo,
          out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern bool CreateProcess(
          string lpApplicationName,
          string lpCommandLine,
          IntPtr lpProcessAttributes,
          IntPtr lpThreadAttributes,
          bool bInheritHandles,
          CreateProcessFlags dwCreationFlags,
          IntPtr lpEnvironment,
          string lpCurrentDirectory,
          [In] STARTUPINFOEX lpStartupInfo,
          out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern bool CreateProcessWithLogonW(
          string lpUsername,
          string lpDomain,
          string lpPassword,
          CreateProcessLogonFlags dwLogonFlags,
          string lpApplicationName,
          string lpCommandLine,
          CreateProcessFlags dwCreationFlags,
          IntPtr lpEnvironment,
          string lpCurrentDirectory,
          ref STARTUPINFO lpStartupInfo,
          out PROCESS_INFORMATION lpProcessInformation);

        public static Win32Process CreateProcessAsUser(NtToken token, string application_name, string command_line, CreateProcessFlags flags, string desktop)
        {
            STARTUPINFO start_info = new STARTUPINFO();
            start_info.cb = Marshal.SizeOf(start_info);
            start_info.lpDesktop = desktop;
            PROCESS_INFORMATION proc_info = new PROCESS_INFORMATION();

            if (!CreateProcessAsUser(token.Handle, application_name, command_line, 
                IntPtr.Zero, IntPtr.Zero, false, flags, IntPtr.Zero, null, ref start_info, out proc_info))
            {
                if (!CreateProcessWithTokenW(token.Handle, 0, application_name, command_line, 
                    flags, IntPtr.Zero, null, ref start_info, out proc_info))
                {
                    throw new SafeWin32Exception();
                }
            }

            return new Win32Process(proc_info);
        }

        public static Win32Process CreateProcessWithLogin(string username, string domain, string password, CreateProcessLogonFlags logon_flags,
            string application_name, string command_line, CreateProcessFlags flags, string desktop)
        {
            STARTUPINFO start_info = new STARTUPINFO();
            start_info.cb = Marshal.SizeOf(start_info);
            start_info.lpDesktop = desktop;
            PROCESS_INFORMATION proc_info = new PROCESS_INFORMATION();

            if (!CreateProcessWithLogonW(username, domain, password, logon_flags, application_name, command_line,
                flags, IntPtr.Zero, null, ref start_info, out proc_info))
            {
                throw new SafeWin32Exception();
            }

            return new Win32Process(proc_info);
        }

        public static Win32Process CreateProcess(NtProcess parent, string application_name, string command_line, CreateProcessFlags flags, string desktop)
        {
            STARTUPINFOEX start_info = new STARTUPINFOEX();
            start_info.StartupInfo.lpDesktop = desktop;
            PROCESS_INFORMATION proc_info = new PROCESS_INFORMATION();

            using (SafeProcThreadAttributeListBuffer attr_list = new SafeProcThreadAttributeListBuffer(1))
            {
                using (var handle_buffer = parent.Handle.DangerousGetHandle().ToBuffer())
                {
                    attr_list.AddAttribute(new IntPtr(0x00020000), handle_buffer);
                    start_info.lpAttributeList = attr_list.DangerousGetHandle();
                    
                    if (!CreateProcess(application_name, command_line, IntPtr.Zero, IntPtr.Zero, false, 
                        flags | CreateProcessFlags.EXTENDED_STARTUPINFO_PRESENT, IntPtr.Zero, null, start_info, out proc_info))
                    {
                        throw new SafeWin32Exception();
                    }

                    return new Win32Process(proc_info);
                }
            }
        }

        public void Dispose()
        {
            if (Process != null)
            {
                Process.Dispose();
            }
            if (Thread != null)
            {
                Thread.Dispose();
            }
        }

        public NtProcess Process { get; private set; }
        public NtThread Thread { get; private set; }
        public int Pid { get; private set; }
        public int Tid { get; private set; }

        internal Win32Process(PROCESS_INFORMATION proc_info)
        {
            Process = NtProcess.FromHandle(new SafeKernelObjectHandle(proc_info.hProcess, true));
            Thread = NtThread.FromHandle(new SafeKernelObjectHandle(proc_info.hThread, true));
            Pid = proc_info.dwProcessId;
            Tid = proc_info.dwThreadId;
        }
    }
}
