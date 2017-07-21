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
        BreakawayFromJob = 0x01000000,
        DefaultErrorMode = 0x04000000,
        NewConsole = 0x00000010,
        NewProcessGroup = 0x00000200,
        NoWindow = 0x08000000,
        ProtectedProcess = 0x00040000,
        PreserveCodeAuthZLevel = 0x02000000,
        SeparateWowVdm = 0x00000800,
        SharedWowVdm = 0x00001000,
        Suspended = 0x00000004,
        UnicodeEnvironment = 0x00000400,
        DebugOnlyThisProcess = 0x00000002,
        DebugProcess = 0x00000001,
        DetachedProcess = 0x00000008,
        ExtendedStartupInfoPresent = 0x00080000,
        InheritParentAffinity = 0x00010000
    }

    [Flags]
    public enum CreateProcessLogonFlags
    {
        None = 0,
        WithProfile = 1,
        NetCredentialsOnly = 2,
    }

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

    [StructLayout(LayoutKind.Sequential)]
    class SECURITY_ATTRIBUTES
    {
        public int nLength;
        public SafeBuffer lpSecurityDescriptor;
        [MarshalAs(UnmanagedType.Bool)]
        public bool bInheritHandle;

        public SECURITY_ATTRIBUTES()
        {
            nLength = Marshal.SizeOf(this);
            lpSecurityDescriptor = SafeHGlobalBuffer.Null;
        }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    class STARTUPINFOEX
    {
        public STARTUPINFO StartupInfo;
        public SafeBuffer lpAttributeList;

        public STARTUPINFOEX()
        {
            StartupInfo.cb = Marshal.SizeOf(this);
            lpAttributeList = SafeHGlobalBuffer.Null;
        }
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

    public class ProcessCreateConfiguration
    {
        public SecurityDescriptor ProcessSecurityDescriptor { get; set; }
        public bool InheritProcessHandle { get; set; }
        public SecurityDescriptor ThreadSecurityDescriptor { get; set; }
        public bool InheritThreadHandle { get; set; }
        public bool InheritHandles { get; set; }
        public NtProcess ParentProcess { get; set; }
        public string ApplicationName { get; set; }
        public string CommandLine { get; set; }
        public CreateProcessFlags CreationFlags { get; set; }
        public byte[] Environment { get; set; }
        public string CurrentDirectory { get; set; }
        public string Desktop { get; set; }
        public string Title { get; set; }

        private void PopulateStartupInfo(ref STARTUPINFO start_info)
        {
            start_info.lpDesktop = Desktop;
            start_info.lpTitle = Title;
        }

        internal STARTUPINFO ToStartupInfo()
        {
            STARTUPINFO start_info = new STARTUPINFO();
            start_info.cb = Marshal.SizeOf(start_info);
            PopulateStartupInfo(ref start_info);
            return start_info;
        }

        private int GetAttributeCount()
        {
            int count = 0;
            if (ParentProcess != null)
            {
                count++;
            }
            return count;
        }

        private SafeHGlobalBuffer GetAttributes(DisposableList<IDisposable> resources)
        {
            int count = GetAttributeCount();
            if (count == 0)
            {
                return SafeHGlobalBuffer.Null;
            }

            var attr_list = resources.AddResource(new SafeProcThreadAttributeListBuffer(count));
            if (ParentProcess != null)
            {
                var handle_buffer = resources.AddResource(ParentProcess.Handle.DangerousGetHandle().ToBuffer());
                attr_list.AddAttribute(new IntPtr(0x00020000), handle_buffer);
            }
            return attr_list;
        }

        internal STARTUPINFOEX ToStartupInfoEx(DisposableList<IDisposable> resources)
        {
            STARTUPINFOEX start_info = new STARTUPINFOEX();
            PopulateStartupInfo(ref start_info.StartupInfo);
            start_info.lpAttributeList = GetAttributes(resources);
            return start_info;
        }

        internal SECURITY_ATTRIBUTES ProcessSecurityAttributes(DisposableList<IDisposable> resources)
        {
            return CreateSecurityAttributes(ProcessSecurityDescriptor, InheritProcessHandle, resources);
        }

        internal SECURITY_ATTRIBUTES ThreadSecurityAttributes(DisposableList<IDisposable> resources)
        {            
            return CreateSecurityAttributes(ThreadSecurityDescriptor, InheritThreadHandle, resources);
        }

        private static SECURITY_ATTRIBUTES CreateSecurityAttributes(SecurityDescriptor sd, bool inherit, DisposableList<IDisposable> resources)
        {
            if (sd == null && !inherit)
            {
                return null;
            }
            var ret = new SECURITY_ATTRIBUTES()
            {
                bInheritHandle = inherit
            };
            if (sd != null)
            {
                ret.lpSecurityDescriptor = resources.AddResource(sd.ToSafeBuffer());
            }
            return ret;
        }
    }

    public sealed class Win32Process : IDisposable
    {
        [StructLayout(LayoutKind.Sequential)]
        internal struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern bool CreateProcessAsUser(
          SafeKernelObjectHandle hToken,
          string lpApplicationName,
          string lpCommandLine,
          SECURITY_ATTRIBUTES lpProcessAttributes,
          SECURITY_ATTRIBUTES lpThreadAttributes,
          bool bInheritHandles,
          CreateProcessFlags dwCreationFlags,
          byte[] lpEnvironment,
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
          byte[] lpEnvironment,
          string lpCurrentDirectory,
          ref STARTUPINFO lpStartupInfo,
          out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern bool CreateProcess(
          string lpApplicationName,
          string lpCommandLine,
          [In] SECURITY_ATTRIBUTES lpProcessAttributes,
          [In] SECURITY_ATTRIBUTES lpThreadAttributes,
          bool bInheritHandles,
          CreateProcessFlags dwCreationFlags,
          byte[] lpEnvironment,
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
          byte[] lpEnvironment,
          string lpCurrentDirectory,
          ref STARTUPINFO lpStartupInfo,
          out PROCESS_INFORMATION lpProcessInformation);

        public static Win32Process CreateProcessAsUser(NtToken token, ProcessCreateConfiguration config)
        {
            STARTUPINFO start_info = config.ToStartupInfo();
            PROCESS_INFORMATION proc_info = new PROCESS_INFORMATION();

            using (var resources = new DisposableList<IDisposable>())
            {
                SECURITY_ATTRIBUTES proc_attr = config.ProcessSecurityAttributes(resources);
                SECURITY_ATTRIBUTES thread_attr = config.ThreadSecurityAttributes(resources);
                
                if (!CreateProcessAsUser(token.Handle, config.ApplicationName, config.CommandLine,
                        proc_attr, thread_attr, config.InheritHandles, config.CreationFlags, config.Environment, 
                        config.CurrentDirectory, ref start_info, out proc_info))
                {
                    if (!CreateProcessWithTokenW(token.Handle, 0, config.ApplicationName, config.CommandLine,
                        config.CreationFlags, config.Environment, config.CurrentDirectory, ref start_info, out proc_info))
                    {
                        throw new SafeWin32Exception();
                    }
                }

                return new Win32Process(proc_info);
            }
        }

        public static Win32Process CreateProcessAsUser(NtToken token, string application_name, string command_line, CreateProcessFlags flags, string desktop)
        {
            ProcessCreateConfiguration config = new ProcessCreateConfiguration();
            config.ApplicationName = application_name;
            config.CommandLine = command_line;
            config.CreationFlags = flags;
            config.Desktop = desktop;

            return CreateProcessAsUser(token, config);
        }

        public static Win32Process CreateProcessWithLogin(string username, string domain, string password, 
            CreateProcessLogonFlags logon_flags, ProcessCreateConfiguration config)
        {
            STARTUPINFO start_info = config.ToStartupInfo();
            PROCESS_INFORMATION proc_info = new PROCESS_INFORMATION();

            if (!CreateProcessWithLogonW(username, domain, password, logon_flags, 
                config.ApplicationName, config.CommandLine, config.CreationFlags,
                config.Environment, config.CurrentDirectory, ref start_info, out proc_info))
            {
                throw new SafeWin32Exception();
            }

            return new Win32Process(proc_info);
        }

        public static Win32Process CreateProcessWithLogin(string username, string domain, string password, CreateProcessLogonFlags logon_flags,
            string application_name, string command_line, CreateProcessFlags flags, string desktop)
        {
            ProcessCreateConfiguration config = new ProcessCreateConfiguration();
            config.ApplicationName = application_name;
            config.CommandLine = command_line;
            config.CreationFlags = flags;
            config.Desktop = desktop;
            return CreateProcessWithLogin(username, domain, password, logon_flags, config);
        }

        public static Win32Process CreateProcess(ProcessCreateConfiguration config)
        {
            PROCESS_INFORMATION proc_info = new PROCESS_INFORMATION();

            using (var resources = new DisposableList<IDisposable>())
            {
                SECURITY_ATTRIBUTES proc_attr = config.ProcessSecurityAttributes(resources);
                SECURITY_ATTRIBUTES thread_attr = config.ThreadSecurityAttributes(resources);

                if (!CreateProcess(config.ApplicationName, config.CommandLine, proc_attr, thread_attr, config.InheritHandles,
                        config.CreationFlags | CreateProcessFlags.ExtendedStartupInfoPresent, 
                        config.Environment, config.CurrentDirectory, config.ToStartupInfoEx(resources), out proc_info))
                {
                    throw new SafeWin32Exception();
                }

                return new Win32Process(proc_info);
            }
        }

        public static Win32Process CreateProcess(NtProcess parent, string application_name, string command_line, CreateProcessFlags flags, string desktop)
        {
            ProcessCreateConfiguration config = new ProcessCreateConfiguration();
            config.ParentProcess = parent;
            config.ApplicationName = application_name;
            config.CommandLine = command_line;
            config.CreationFlags = flags;
            config.Desktop = desktop;
            return CreateProcess(config);
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
