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
using System.Collections.Generic;
using System.IO;
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

    [Flags]
    public enum Win32kFilterFlags
    {
        None = 0,
        Enable = 1,
        Audit = 2,
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct Win32kFilterAttribute
    {
        public Win32kFilterFlags Flags;
        public int FilterLevel;
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

    [StructLayout(LayoutKind.Sequential)]
    struct SECURITY_CAPABILITIES
    {
        public IntPtr AppContainerSid;
        public IntPtr Capabilities;
        public int CapabilityCount;
        public int Reserved;
    }

    public enum ProtectionLevel
    {
        Same = -1,
        TcbPPL = 0,
        WindowsPP = 1,
        WindowsPPL = 2,
        AntimalwarePPL = 3,
        LsaPPL = 4,
        TcbPP = 5,
        CodeGenPPL = 6,
        AuthenticodePP = 7
    }

    class ProcessAttributes
    {
        const int PROC_THREAD_ATTRIBUTE_THREAD = 0x00010000;
        const int PROC_THREAD_ATTRIBUTE_INPUT = 0x00020000;
        const int PROC_THREAD_ATTRIBUTE_ADDITIVE = 0x00040000;

        static IntPtr GetValue(PROC_THREAD_ATTRIBUTE_NUM Number, bool Thread, bool Input, bool Additive)
        {
            int ret = (int)Number;
            if (Thread)
            {
                ret |= PROC_THREAD_ATTRIBUTE_THREAD;
            }
            if (Input)
            {
                ret |= PROC_THREAD_ATTRIBUTE_INPUT;
            }
            if (Additive)
            {
                ret |= PROC_THREAD_ATTRIBUTE_ADDITIVE;
            }
            return new IntPtr(ret);
        }

        enum PROC_THREAD_ATTRIBUTE_NUM
        {
            ProcThreadAttributeParentProcess = 0,
            ProcThreadAttributeHandleList = 2,
            ProcThreadAttributeGroupAffinity = 3,
            ProcThreadAttributePreferredNode = 4,
            ProcThreadAttributeIdealProcessor = 5,
            ProcThreadAttributeUmsThread = 6,
            ProcThreadAttributeMitigationPolicy = 7,
            ProcThreadAttributeSecurityCapabilities = 9,
            ProcThreadAttributeProtectionLevel = 11,
            ProcThreadAttributeJobList = 13,
            ProcThreadAttributeChildProcessPolicy = 14,
            ProcThreadAttributeAllApplicationPackagesPolicy = 15,
            ProcThreadAttributeWin32kFilter = 16,
            ProcThreadAttributeSafeOpenPromptOriginClaim = 17,
            ProcThreadAttributeDesktopAppPolicy = 18,
        }

        public static IntPtr ProcThreadAttributeParentProcess
        {
            get
            {
                return GetValue(PROC_THREAD_ATTRIBUTE_NUM.ProcThreadAttributeParentProcess, false, true, false);
            }
        }

        public static IntPtr ProcThreadAttributeHandleList
        {
            get
            {
                return GetValue(PROC_THREAD_ATTRIBUTE_NUM.ProcThreadAttributeHandleList, false, true, false);
            }
        }

        public static IntPtr ProcThreadAttributeMitigationPolicy
        {
            get
            {
                return GetValue(PROC_THREAD_ATTRIBUTE_NUM.ProcThreadAttributeMitigationPolicy, false, true, false);
            }
        }

        public static IntPtr ProcThreadAttributeChildProcessPolicy
        {
            get
            {
                return GetValue(PROC_THREAD_ATTRIBUTE_NUM.ProcThreadAttributeChildProcessPolicy, false, true, false);
            }
        }

        public static IntPtr ProcThreadAttributeWin32kFilter
        {
            get
            {
                return GetValue(PROC_THREAD_ATTRIBUTE_NUM.ProcThreadAttributeWin32kFilter, false, true, false);
            }
        }

        public static IntPtr ProcThreadAttributeAllApplicationPackagesPolicy
        {
            get
            {
                return GetValue(PROC_THREAD_ATTRIBUTE_NUM.ProcThreadAttributeAllApplicationPackagesPolicy, false, true, false);
            }
        }

        public static IntPtr ProcThreadAttributeProtectionLevel
        {
            get
            {
                return GetValue(PROC_THREAD_ATTRIBUTE_NUM.ProcThreadAttributeProtectionLevel, false, true, false);
            }
        }

        public static IntPtr ProcThreadAttributeSecurityCapabilities
        {
            get
            {
                return GetValue(PROC_THREAD_ATTRIBUTE_NUM.ProcThreadAttributeSecurityCapabilities, false, true, false);
            }
        }
    }

    class SafeProcThreadAttributeListBuffer : SafeHGlobalBuffer
    {
        private DisposableList<IDisposable> _values = new DisposableList<IDisposable>();

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

        public void AddAttribute<T>(IntPtr attribute, T value) where T : struct
        {
            AddAttributeBuffer(attribute, _values.AddResource(value.ToBuffer()));
        }

        public void AddAttribute(IntPtr attribute, byte[] value)
        {
            AddAttributeBuffer(attribute, _values.AddResource(new SafeHGlobalBuffer(value)));
        }

        public void AddAttributeBuffer(IntPtr attribute, SafeHGlobalBuffer value)
        {
            if (!UpdateProcThreadAttribute(handle, 0, attribute, value.DangerousGetHandle(), 
                new IntPtr(value.Length), IntPtr.Zero, IntPtr.Zero))
            {
                throw new SafeWin32Exception();
            }
        }

        protected override bool ReleaseHandle()
        {
            _values?.Dispose();
            if (!IsInvalid)
            {
                bool ret = DeleteProcThreadAttributeList(handle);
                return base.ReleaseHandle() && ret;
            }

            return false;
        }
    }

    [Flags]
    public enum ProcessMitigationOptions : ulong
    {
        None = 0,
        DepEnable = 0x01,
        DepAtlThunkEnable = 0x02,
        SehopEnable = 0x04,
        ForceRelocateImagesAlwaysOn = (0x00000001 << 8),
        ForceRelocateImagesAlwaysOff = (0x00000002 << 8),
        ForceRelocateImagesAlwaysOnRequireRelocs = (0x00000003 << 8),
        HeapTerminateAlwaysOn = (0x00000001 << 12),
        HeapTerminateAlwaysOff = (0x00000002 << 12),
        BottomUpAslrAlwaysOn = (0x00000001 << 16),
        BottomUpAslrAlwaysOff = (0x00000002 << 16),
        HighEntropyAslrAlwaysOn = (0x00000001 << 20),
        HighEntropyAslrAlwaysOff = (0x00000002 << 20),
        StrictHandleChecksAlwaysOn = (0x00000001 << 24),
        StrictHandleChecksAlwaysOff = (0x00000002 << 24),
        Win32kSystemCallDisableAlwaysOn = (0x00000001 << 28),
        Win32kSystemCallDisableAlwaysOff = (0x00000002 << 28),
        ExtensionPointDisableAlwaysOn = (0x00000001UL << 32),
        ExtensionPointDisableAlwaysOff = (0x00000002UL << 32),
        ProhibitDynamicCodeAlwaysOn = (0x00000001UL << 36),
        ProhibitDynamicCodeAlwaysOff = (0x00000002UL << 36),
        ProhibitDynamicCodeAlwaysOnAllowOptOut = (0x00000003UL << 36),
        ControlFlowGuardAlwaysOn = (0x00000001UL << 40),
        ControlFlowGuardAlwaysOff = (0x00000002UL << 40),
        ControlFlowGuardExportSupression = (0x00000003UL << 40),
        BlockNonMicrosoftBinariesAlwaysOn = (0x00000001UL << 44),
        BlockNonMicrosoftBinariesAlwaysOff = (0x00000002UL << 44),
        BlockNonMicrosoftBinariesAllowStore = (0x00000003UL << 44),
        FontDisableAlwaysOn = (0x00000001UL << 48),
        FontDisableAlwaysOff = (0x00000002UL << 48),
        AuditNonSystemFonts = (0x00000003UL << 48),
        ImageLoadNoRemoteAlwaysOn = (0x00000001UL << 52),
        ImageLoadNoRemoteAlwaysOff = (0x00000002UL << 52),
        ImageLoadNoLowLabelAlwaysOn = (0x00000001UL << 56),
        ImageLoadNoLowLabelAlwaysOff = (0x00000002UL << 56),
        ImageLoadPreferSystem32AlwaysOn = (0x00000001UL << 60),
        ImageLoadPreferSystem32AlwaysOff = (0x00000002UL << 60),
    }

    public enum ProcessMitigationOptions2 : ulong
    {
        None = 0,
        LoadIntegrityContinuityAlwaysOn = (0x00000001UL << 4),
        LoadIntegrityContinuityAlwaysOff = (0x00000002UL << 4),
        LoadIntegrityContinuityAudit = (0x00000003UL << 4),
        StrictControlFlowGuardAlwaysOn = (0x00000001UL << 8),
        StrictControlFlowGuardAlwaysOff = (0x00000002UL << 8)
    }

    public class Win32ProcessConfig
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
        public bool TerminateOnDispose { get; set; }
        public ProcessMitigationOptions MitigationOptions { get; set; }
        public ProcessMitigationOptions2 MitigationOptions2 { get; set; }
        public Win32kFilterFlags Win32kFilterFlags { get; set; }
        public int Win32kFilterLevel { get; set; }
        public ProtectionLevel ProtectionLevel { get; set; }
        public List<IntPtr> InheritHandleList { get; private set; }
        public Sid AppContainerSid { get; set; }
        public List<Sid> Capabilities { get; private set; }

        public Win32ProcessConfig()
        {
            InheritHandleList = new List<IntPtr>();
            Capabilities = new List<Sid>();
        }

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
            if ((MitigationOptions != ProcessMitigationOptions.None) 
                || (MitigationOptions2 != ProcessMitigationOptions2.None))
            {
                count++;
            }

            if (Win32kFilterFlags != Win32kFilterFlags.None)
            {
                count++;
            }

            if ((CreationFlags & CreateProcessFlags.ProtectedProcess) != 0)
            {
                count++;
            }

            if (InheritHandleList.Count > 0)
            {
                count++;
            }

            if (AppContainerSid != null)
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
                attr_list.AddAttribute(ProcessAttributes.ProcThreadAttributeParentProcess, ParentProcess.Handle.DangerousGetHandle());
            }

            if (MitigationOptions2 != ProcessMitigationOptions2.None)
            {
                MemoryStream stm = new MemoryStream();
                BinaryWriter writer = new BinaryWriter(stm);

                writer.Write((ulong)MitigationOptions);
                writer.Write((ulong)MitigationOptions2);
                attr_list.AddAttribute(ProcessAttributes.ProcThreadAttributeMitigationPolicy, stm.ToArray());
            }
            else if (MitigationOptions != ProcessMitigationOptions.None)
            {
                attr_list.AddAttribute(ProcessAttributes.ProcThreadAttributeMitigationPolicy, (ulong)MitigationOptions);
            }

            if (Win32kFilterFlags != Win32kFilterFlags.None)
            {
                Win32kFilterAttribute filter = new Win32kFilterAttribute();
                filter.Flags = Win32kFilterFlags;
                filter.FilterLevel = Win32kFilterLevel;
                attr_list.AddAttributeBuffer(ProcessAttributes.ProcThreadAttributeWin32kFilter, resources.AddResource(filter.ToBuffer()));
            }

            if ((CreationFlags & CreateProcessFlags.ProtectedProcess) != 0)
            {
                attr_list.AddAttribute(ProcessAttributes.ProcThreadAttributeProtectionLevel, (int)ProtectionLevel);
            }

            if (InheritHandleList.Count > 0)
            {
                int total_size = IntPtr.Size * InheritHandleList.Count;
                var handle_list = resources.AddResource(new SafeHGlobalBuffer(total_size));
                handle_list.WriteArray(0, InheritHandleList.ToArray(), 0, InheritHandleList.Count);
                attr_list.AddAttributeBuffer(ProcessAttributes.ProcThreadAttributeHandleList, handle_list);
            }

            if (AppContainerSid != null)
            {
                SECURITY_CAPABILITIES caps = new SECURITY_CAPABILITIES();
                caps.AppContainerSid = resources.AddResource(AppContainerSid.ToSafeBuffer()).DangerousGetHandle();
                
                if (Capabilities.Count > 0)
                {
                    SidAndAttributes[] cap_sids = new SidAndAttributes[Capabilities.Count];
                    for (int i = 0; i < Capabilities.Count; ++i)
                    {
                        cap_sids[i] = new SidAndAttributes()
                        {
                            Sid = resources.AddResource(Capabilities[i].ToSafeBuffer()).DangerousGetHandle(),
                            Attributes = GroupAttributes.Enabled
                        };
                    }
                    SafeHGlobalBuffer cap_buffer = resources.AddResource(new SafeHGlobalBuffer(Marshal.SizeOf(typeof(SidAndAttributes)) * Capabilities.Count));
                    cap_buffer.WriteArray(0, cap_sids, 0, cap_sids.Length);
                    caps.Capabilities = cap_buffer.DangerousGetHandle();
                    caps.CapabilityCount = cap_sids.Length;
                }
                attr_list.AddAttribute(ProcessAttributes.ProcThreadAttributeSecurityCapabilities, caps);
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

        private static SECURITY_ATTRIBUTES CreateSecurityAttributes(SecurityDescriptor sd, 
            bool inherit, DisposableList<IDisposable> resources)
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
          [In] STARTUPINFOEX lpStartupInfo,
          out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern bool CreateProcessWithTokenW(
          SafeKernelObjectHandle hToken,
          CreateProcessLogonFlags dwLogonFlags,
          string lpApplicationName,
          string lpCommandLine,
          CreateProcessFlags dwCreationFlags,
          [In] byte[] lpEnvironment,
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
          [In] byte[] lpEnvironment,
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
          [In] byte[] lpEnvironment,
          string lpCurrentDirectory,
          ref STARTUPINFO lpStartupInfo,
          out PROCESS_INFORMATION lpProcessInformation);

        public static Win32Process CreateProcessAsUser(NtToken token, Win32ProcessConfig config)
        {
            using (var resources = new DisposableList<IDisposable>())
            {
                PROCESS_INFORMATION proc_info = new PROCESS_INFORMATION();
                STARTUPINFOEX start_info = config.ToStartupInfoEx(resources);
                SECURITY_ATTRIBUTES proc_attr = config.ProcessSecurityAttributes(resources);
                SECURITY_ATTRIBUTES thread_attr = config.ThreadSecurityAttributes(resources);
                
                if (!CreateProcessAsUser(token.Handle, config.ApplicationName, config.CommandLine,
                        proc_attr, thread_attr, config.InheritHandles, config.CreationFlags 
                        | CreateProcessFlags.ExtendedStartupInfoPresent, config.Environment, 
                        config.CurrentDirectory, start_info, out proc_info))
                {
                    if (!CreateProcessWithTokenW(token.Handle, 0, config.ApplicationName, config.CommandLine,
                        config.CreationFlags, config.Environment, config.CurrentDirectory, 
                        ref start_info.StartupInfo, out proc_info))
                    {
                        throw new SafeWin32Exception();
                    }
                }

                return new Win32Process(proc_info, config.TerminateOnDispose);
            }
        }

        public static Win32Process CreateProcessAsUser(NtToken token, string application_name, string command_line, CreateProcessFlags flags, string desktop)
        {
            Win32ProcessConfig config = new Win32ProcessConfig();
            config.ApplicationName = application_name;
            config.CommandLine = command_line;
            config.CreationFlags = flags;
            config.Desktop = desktop;

            return CreateProcessAsUser(token, config);
        }

        public static Win32Process CreateProcessWithLogin(string username, string domain, string password, 
            CreateProcessLogonFlags logon_flags, Win32ProcessConfig config)
        {
            STARTUPINFO start_info = config.ToStartupInfo();
            PROCESS_INFORMATION proc_info = new PROCESS_INFORMATION();

            if (!CreateProcessWithLogonW(username, domain, password, logon_flags, 
                config.ApplicationName, config.CommandLine, config.CreationFlags,
                config.Environment, config.CurrentDirectory, ref start_info, out proc_info))
            {
                throw new SafeWin32Exception();
            }

            return new Win32Process(proc_info, config.TerminateOnDispose);
        }

        public static Win32Process CreateProcessWithLogin(string username, string domain, string password, CreateProcessLogonFlags logon_flags,
            string application_name, string command_line, CreateProcessFlags flags, string desktop)
        {
            Win32ProcessConfig config = new Win32ProcessConfig();
            config.ApplicationName = application_name;
            config.CommandLine = command_line;
            config.CreationFlags = flags;
            config.Desktop = desktop;
            return CreateProcessWithLogin(username, domain, password, logon_flags, config);
        }

        public static Win32Process CreateProcess(Win32ProcessConfig config)
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

                return new Win32Process(proc_info, config.TerminateOnDispose);
            }
        }

        public static Win32Process CreateProcess(NtProcess parent, string application_name, string command_line, CreateProcessFlags flags, string desktop)
        {
            Win32ProcessConfig config = new Win32ProcessConfig();
            config.ParentProcess = parent;
            config.ApplicationName = application_name;
            config.CommandLine = command_line;
            config.CreationFlags = flags;
            config.Desktop = desktop;
            return CreateProcess(config);
        }

        public void Dispose()
        {
            if (TerminateOnDispose)
            {
                try
                {
                    Process?.Terminate(NtStatus.STATUS_PROCESS_IS_TERMINATING);
                }
                catch (NtException)
                {
                }
            }
            Process?.Dispose();
            Thread?.Dispose();
        }

        public NtProcess Process { get; private set; }
        public NtThread Thread { get; private set; }
        public int Pid { get; private set; }
        public int Tid { get; private set; }
        public bool TerminateOnDispose { get; set; }

        internal Win32Process(PROCESS_INFORMATION proc_info, bool terminate_on_dispose)
        {
            Process = NtProcess.FromHandle(new SafeKernelObjectHandle(proc_info.hProcess, true));
            Thread = NtThread.FromHandle(new SafeKernelObjectHandle(proc_info.hThread, true));
            Pid = proc_info.dwProcessId;
            Tid = proc_info.dwThreadId;
            TerminateOnDispose = terminate_on_dispose;
        }
    }
}
