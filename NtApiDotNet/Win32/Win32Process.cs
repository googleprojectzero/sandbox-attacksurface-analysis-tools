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

using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace NtApiDotNet.Win32
{
    /// <summary>
    /// Flags for create process.
    /// </summary>
    [Flags]
    public enum CreateProcessFlags
    {
        /// <summary>
        /// No flags.
        /// </summary>
        None = 0,
        /// <summary>
        /// Breakaway from a job object.
        /// </summary>
        BreakawayFromJob = 0x01000000,
        /// <summary>
        /// Default error mode.
        /// </summary>
        DefaultErrorMode = 0x04000000,
        /// <summary>
        /// Create a new console.
        /// </summary>
        NewConsole = 0x00000010,
        /// <summary>
        /// Create a new process group.
        /// </summary>
        NewProcessGroup = 0x00000200,
        /// <summary>
        /// No window.
        /// </summary>
        NoWindow = 0x08000000,
        /// <summary>
        /// Create a protected process.
        /// </summary>
        ProtectedProcess = 0x00040000,
        /// <summary>
        /// Preserve code authz level.
        /// </summary>
        PreserveCodeAuthZLevel = 0x02000000,
        /// <summary>
        /// Create a separate WOW VDM.
        /// </summary>
        SeparateWowVdm = 0x00000800,
        /// <summary>
        /// Share the WOW VDM.
        /// </summary>
        SharedWowVdm = 0x00001000,
        /// <summary>
        /// Create suspended.
        /// </summary>
        Suspended = 0x00000004,
        /// <summary>
        /// Create from a unicode environment.
        /// </summary>
        UnicodeEnvironment = 0x00000400,
        /// <summary>
        /// Debug only this process.
        /// </summary>
        DebugOnlyThisProcess = 0x00000002,
        /// <summary>
        /// Debug process.
        /// </summary>
        DebugProcess = 0x00000001,
        /// <summary>
        /// Detach process.
        /// </summary>
        DetachedProcess = 0x00000008,
        /// <summary>
        /// Specify extended startup information is present.
        /// </summary>
        ExtendedStartupInfoPresent = 0x00080000,
        /// <summary>
        /// Inherit parent affinity.
        /// </summary>
        InheritParentAffinity = 0x00010000
    }

    /// <summary>
    /// Flags for CreateProcessWithLogon
    /// </summary>
    [Flags]
    public enum CreateProcessLogonFlags
    {
        /// <summary>
        /// No flags.
        /// </summary>
        None = 0,
        /// <summary>
        /// With a profile.
        /// </summary>
        WithProfile = 1,
        /// <summary>
        /// Using network credentials.
        /// </summary>
        NetCredentialsOnly = 2,
    }

    /// <summary>
    /// Win32k filter flags.
    /// </summary>
    [Flags]
    public enum Win32kFilterFlags
    {
        /// <summary>
        /// No flags.
        /// </summary>
        None = 0,
        /// <summary>
        /// Enable filter.
        /// </summary>
        Enable = 1,
        /// <summary>
        /// Audit filter.
        /// </summary>
        Audit = 2,
    }

    [StructLayout(LayoutKind.Sequential)]
    struct Win32kFilterAttribute
    {
        public Win32kFilterFlags Flags;
        public int FilterLevel;
    }

    [Flags]
    enum STARTF : uint
    {
        STARTF_USESHOWWINDOW = 0x00000001,
        STARTF_USESIZE = 0x00000002,
        STARTF_USEPOSITION = 0x00000004,
        STARTF_USECOUNTCHARS = 0x00000008,
        STARTF_USEFILLATTRIBUTE = 0x00000010,
        STARTF_RUNFULLSCREEN = 0x00000020,
        STARTF_FORCEONFEEDBACK = 0x00000040,
        STARTF_FORCEOFFFEEDBACK = 0x00000080,
        STARTF_USESTDHANDLES = 0x00000100,
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct STARTUPINFO
    {
        public int cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public int dwX;
        public int dwY;
        public int dwXSize;
        public int dwYSize;
        public int dwXCountChars;
        public int dwYCountChars;
        public int dwFillAttribute;
        public STARTF dwFlags;
        public short wShowWindow;
        public short cbReserved2;
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

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct BnoIsolationAttribute
    {
        public int IsolationEnabled;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 136)]
        public string IsolationPrefix;
    }

    /// <summary>
    /// Specify PPL level.
    /// </summary>
    public enum ProtectionLevel
    {
        /// <summary>
        /// None
        /// </summary>
        None = -2,
        /// <summary>
        /// Safe level as parent.
        /// </summary>
        Same = -1,
        /// <summary>
        /// Tcb PPL
        /// </summary>
        TcbPPL = 0,
        /// <summary>
        /// Windows PP
        /// </summary>
        WindowsPP = 1,
        /// <summary>
        /// Windows PPL
        /// </summary>
        WindowsPPL = 2,
        /// <summary>
        /// Antimalware PPL
        /// </summary>
        AntimalwarePPL = 3,
        /// <summary>
        /// LSA PPL
        /// </summary>
        LsaPPL = 4,
        /// <summary>
        /// Tcb PP
        /// </summary>
        TcbPP = 5,
        /// <summary>
        /// Code Generation PPL
        /// </summary>
        CodeGenPPL = 6,
        /// <summary>
        /// Authenticode PP
        /// </summary>
        AuthenticodePP = 7,
        /// <summary>
        /// App PPL
        /// </summary>
        AppPPL = 8
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
            ProcThreadAttributePackageName = 8,
            ProcThreadAttributeSecurityCapabilities = 9,
            ProcThreadAttributeProtectionLevel = 11,
            ProcThreadAttributeJobList = 13,
            ProcThreadAttributeChildProcessPolicy = 14,
            ProcThreadAttributeAllApplicationPackagesPolicy = 15,
            ProcThreadAttributeWin32kFilter = 16,
            ProcThreadAttributeSafeOpenPromptOriginClaim = 17,
            ProcThreadAttributeDesktopAppPolicy = 18,
            ProcThreadAttributeBnoIsolation = 19,
            ProcThreadAttributePseudoConsole = 22,
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

        public static IntPtr ProcThreadAttributeDesktopAppPolicy
        {
            get
            {
                return GetValue(PROC_THREAD_ATTRIBUTE_NUM.ProcThreadAttributeDesktopAppPolicy, false, true, false);
            }
        }

        public static IntPtr ProcThreadAttributePackageName
        {
            get
            {
                return GetValue(PROC_THREAD_ATTRIBUTE_NUM.ProcThreadAttributePackageName, false, true, false);
            }
        }

        public static IntPtr ProcThreadAttributePseudoConsole
        {
            get
            {
                return GetValue(PROC_THREAD_ATTRIBUTE_NUM.ProcThreadAttributePseudoConsole, false, true, false);
            }
        }

        public static IntPtr ProcThreadAttributeBnoIsolation
        {
            get
            {
                return GetValue(PROC_THREAD_ATTRIBUTE_NUM.ProcThreadAttributeBnoIsolation, false, true, false);
            }
        }

        public static IntPtr ProcThreadAttributeSafeOpenPromptOriginClaim
        {
            get
            {
                return GetValue(PROC_THREAD_ATTRIBUTE_NUM.ProcThreadAttributeSafeOpenPromptOriginClaim, false, true, false);
            }
        }
    }

    class SafeProcThreadAttributeListBuffer : SafeHGlobalBuffer
    {
        private DisposableList<IDisposable> _values = new DisposableList<IDisposable>();

        private static int GetAttributeListSize(int count)
        {
            IntPtr size = IntPtr.Zero;
            Win32NativeMethods.InitializeProcThreadAttributeList(IntPtr.Zero, count, 0, ref size);
            return size.ToInt32();
        }

        public SafeProcThreadAttributeListBuffer(int count) : base(GetAttributeListSize(count))
        {
            IntPtr size = new IntPtr(Length);
            if (!Win32NativeMethods.InitializeProcThreadAttributeList(handle, count, 0, ref size))
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
            if (!Win32NativeMethods.UpdateProcThreadAttribute(handle, 0, attribute, value.DangerousGetHandle(), 
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
                bool ret = Win32NativeMethods.DeleteProcThreadAttributeList(handle);
                return base.ReleaseHandle() && ret;
            }

            return false;
        }
    }

    internal class ScopedDebugObject : IDisposable
    {
        private readonly NtDebug _debug_object;
        private readonly IntPtr _old_debug_object_handle;

        public ScopedDebugObject(NtDebug debug_object)
        {
            _debug_object = debug_object;
            _old_debug_object_handle = NtDbgUi.DbgUiGetThreadDebugObject();
            NtDbgUi.DbgUiSetThreadDebugObject(debug_object.Handle.DangerousGetHandle());
        }

        public void Dispose()
        {
            NtDbgUi.DbgUiSetThreadDebugObject(_old_debug_object_handle);
        }
    }

#pragma warning disable 1591
    /// <summary>
    /// Process mitigation option flags.
    /// </summary>
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

    /// <summary>
    /// Process mitigation option 2 flags.
    /// </summary>
    public enum ProcessMitigationOptions2 : ulong
    {
        None = 0,
        LoadIntegrityContinuityAlwaysOn = (0x00000001UL << 4),
        LoadIntegrityContinuityAlwaysOff = (0x00000002UL << 4),
        LoadIntegrityContinuityAudit = (0x00000003UL << 4),
        StrictControlFlowGuardAlwaysOn = (0x00000001UL << 8),
        StrictControlFlowGuardAlwaysOff = (0x00000002UL << 8),
        ModuleTamperingProtectionAlwaysOn = (0x00000001UL << 12),
        ModuleTamperingProtectionAlwaysOff = (0x00000002UL << 12),
        ModuleTamperingProtectionNoInherit  = (0x00000003UL << 12),
    }

    [Flags]
    public enum ProcessDesktopAppBreakawayFlags
    {
        None = 0,
        Enable = 1,
        Disable = 2,
        Override = 4
    }
#pragma warning restore

    /// <summary>
    /// Win32 process creation configuration.
    /// </summary>
    public class Win32ProcessConfig
    {
        /// <summary>
        /// Specify security descriptor of process.
        /// </summary>
        public SecurityDescriptor ProcessSecurityDescriptor { get; set; }
        /// <summary>
        /// Specify process handle is inheritable.
        /// </summary>
        public bool InheritProcessHandle { get; set; }
        /// <summary>
        /// Specify security descriptor of thread.
        /// </summary>
        public SecurityDescriptor ThreadSecurityDescriptor { get; set; }
        /// <summary>
        /// Specify thread handle is inheritable.
        /// </summary>
        public bool InheritThreadHandle { get; set; }
        /// <summary>
        /// Specify to inherit handles.
        /// </summary>
        public bool InheritHandles { get; set; }
        /// <summary>
        /// Specify parent process.
        /// </summary>
        public NtProcess ParentProcess { get; set; }
        /// <summary>
        /// Specify path to application executable.
        /// </summary>
        public string ApplicationName { get; set; }
        /// <summary>
        /// Specify command line.
        /// </summary>
        public string CommandLine { get; set; }
        /// <summary>
        /// Specify creation flags.
        /// </summary>
        public CreateProcessFlags CreationFlags { get; set; }
        /// <summary>
        /// Specify environment block.
        /// </summary>
        public byte[] Environment { get; set; }
        /// <summary>
        /// Specify current directory.
        /// </summary>
        public string CurrentDirectory { get; set; }
        /// <summary>
        /// Specify desktop name.
        /// </summary>
        public string Desktop { get; set; }
        /// <summary>
        /// Specify window title.
        /// </summary>
        public string Title { get; set; }
        /// <summary>
        /// True to terminate the process when it's disposed.
        /// </summary>
        public bool TerminateOnDispose { get; set; }
        /// <summary>
        /// Specify the mitigation options.
        /// </summary>
        public ProcessMitigationOptions MitigationOptions { get; set; }
        /// <summary>
        /// Specify the mitigation options 2.
        /// </summary>
        public ProcessMitigationOptions2 MitigationOptions2 { get; set; }
        /// <summary>
        /// Specify win32k filter flags.
        /// </summary>
        public Win32kFilterFlags Win32kFilterFlags { get; set; }
        /// <summary>
        /// Specify win32k filter level.
        /// </summary>
        public int Win32kFilterLevel { get; set; }
        /// <summary>
        /// Specify PP level.
        /// </summary>
        public ProtectionLevel ProtectionLevel { get; set; }
        /// <summary>
        /// Specify list of handles to inherit.
        /// </summary>
        public List<IntPtr> InheritHandleList { get; private set; }
        /// <summary>
        /// Specify the appcontainer Sid.
        /// </summary>
        public Sid AppContainerSid { get; set; }
        /// <summary>
        /// Specify the appcontainer capabilities.
        /// </summary>
        public List<Sid> Capabilities { get; private set; }
        /// <summary>
        /// Specify LPAC.
        /// </summary>
        public bool LowPrivilegeAppContainer { get; set; }
        /// <summary>
        /// Restrict the process from creating child processes.
        /// </summary>
        public bool RestrictChildProcessCreation { get; set; }
        /// <summary>
        /// Override child process creation restriction.
        /// </summary>
        public bool OverrideChildProcessCreation { get; set; }
        /// <summary>
        /// Specify new process policy when creating a desktop bridge application.
        /// </summary>
        public ProcessDesktopAppBreakawayFlags DesktopAppBreakaway { get; set; }
        /// <summary>
        /// Specify a token to use for the new process.
        /// </summary>
        public NtToken Token { get; set; }
        /// <summary>
        /// Specify a stdin handle for the new process (you must inherit the handle).
        /// </summary>
        public IntPtr StdInputHandle { get; set; }
        /// <summary>
        /// Specify a stdout handle for the new process (you must inherit the handle).
        /// </summary>
        public IntPtr StdOutputHandle { get; set; }
        /// <summary>
        /// Specify a stderror handle for the new process (you must inherit the handle).
        /// </summary>
        public IntPtr StdErrorHandle { get; set; }
        /// <summary>
        /// Specify the package name to use.
        /// </summary>
        public string PackageName { get; set; }
        /// <summary>
        /// Specify handle to pseudo console.
        /// </summary>
        public IntPtr PseudoConsole { get; set; }
        /// <summary>
        /// Specify Base Named Objects isolation prefix.
        /// </summary>
        public string BnoIsolationPrefix { get; set; }
        /// <summary>
        /// Specify the safe open prompt original claim.
        /// </summary>
        public byte[] SafeOpenPromptOriginClaim { get; set; }
        /// <summary>
        /// When specifying the debug flags use this debug object instead of the current thread's object.
        /// </summary>
        public NtDebug DebugObject { get; set; }
        /// <summary>
        /// When specified do not fallback to using CreateProcessWithLogon if CreateProcessWithUser fails.
        /// </summary>
        public bool NoTokenFallback { get; set; }

        /// <summary>
        /// Add an object's handle to the list of inherited handles. 
        /// </summary>
        /// <param name="obj">The object to add.</param>
        /// <returns>The raw handle value.</returns>
        /// <remarks>Note that this doesn't maintain a reference to the object. It should be kept
        /// alive until the process has been created.</remarks>
        public IntPtr AddInheritedHandle(NtObject obj)
        {
            obj.Inherit = true;
            IntPtr handle = obj.Handle.DangerousGetHandle();
            InheritHandleList.Add(handle);
            return handle;
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        public Win32ProcessConfig()
        {
            InheritHandleList = new List<IntPtr>();
            Capabilities = new List<Sid>();
            StdInputHandle = Win32Utils.InvalidHandle;
            StdOutputHandle = Win32Utils.InvalidHandle;
            StdErrorHandle = Win32Utils.InvalidHandle;
        }

        private void PopulateStartupInfo(ref STARTUPINFO start_info)
        {
            start_info.lpDesktop = Desktop;
            start_info.lpTitle = Title;
            if (StdInputHandle != Win32Utils.InvalidHandle ||
                StdOutputHandle != Win32Utils.InvalidHandle ||
                StdErrorHandle != Win32Utils.InvalidHandle)
            {
                start_info.hStdInput = StdInputHandle;
                start_info.hStdOutput = StdOutputHandle;
                start_info.hStdError = StdErrorHandle;
                start_info.dwFlags = STARTF.STARTF_USESTDHANDLES;
            }
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

            if (LowPrivilegeAppContainer)
            {
                count++;
            }

            if (RestrictChildProcessCreation || OverrideChildProcessCreation)
            {
                count++;
            }

            if (DesktopAppBreakaway != ProcessDesktopAppBreakawayFlags.None)
            {
                count++;
            }

            if (!string.IsNullOrWhiteSpace(PackageName))
            {
                count++;
            }

            if (PseudoConsole != IntPtr.Zero)
            {
                count++;
            }

            if (!string.IsNullOrEmpty(BnoIsolationPrefix))
            {
                count++;
            }

            if (SafeOpenPromptOriginClaim != null)
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
                Win32kFilterAttribute filter = new Win32kFilterAttribute
                {
                    Flags = Win32kFilterFlags,
                    FilterLevel = Win32kFilterLevel
                };
                attr_list.AddAttributeBuffer(ProcessAttributes.ProcThreadAttributeWin32kFilter, resources.AddResource(filter.ToBuffer()));
            }

            if ((CreationFlags & CreateProcessFlags.ProtectedProcess) != 0 && ProtectionLevel != ProtectionLevel.None)
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
                SECURITY_CAPABILITIES caps = new SECURITY_CAPABILITIES
                {
                    AppContainerSid = resources.AddResource(AppContainerSid.ToSafeBuffer()).DangerousGetHandle()
                };

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

            if (LowPrivilegeAppContainer)
            {
                attr_list.AddAttribute(ProcessAttributes.ProcThreadAttributeAllApplicationPackagesPolicy, 1);
            }

            if (RestrictChildProcessCreation || OverrideChildProcessCreation)
            {
                int flags = RestrictChildProcessCreation ? 1 : 0;
                flags |= OverrideChildProcessCreation ? 2 : 0;

                attr_list.AddAttribute(ProcessAttributes.ProcThreadAttributeChildProcessPolicy, flags);
            }

            if (DesktopAppBreakaway != ProcessDesktopAppBreakawayFlags.None)
            {
                attr_list.AddAttribute(ProcessAttributes.ProcThreadAttributeDesktopAppPolicy, (int)DesktopAppBreakaway);
            }

            if (!string.IsNullOrWhiteSpace(PackageName))
            {
                byte[] str_bytes = Encoding.Unicode.GetBytes(PackageName);
                var string_buffer = resources.AddResource(new SafeHGlobalBuffer(str_bytes));
                attr_list.AddAttributeBuffer(ProcessAttributes.ProcThreadAttributePackageName, string_buffer);
            }

            if (PseudoConsole != IntPtr.Zero)
            {
                attr_list.AddAttribute(ProcessAttributes.ProcThreadAttributePseudoConsole, PseudoConsole);
            }

            if (!string.IsNullOrEmpty(BnoIsolationPrefix))
            {
                var prefix = new BnoIsolationAttribute() { IsolationEnabled = 1, IsolationPrefix = BnoIsolationPrefix };
                attr_list.AddAttribute(ProcessAttributes.ProcThreadAttributeBnoIsolation, prefix);
            }

            if (SafeOpenPromptOriginClaim != null)
            {
                var bytes = (byte[])SafeOpenPromptOriginClaim.Clone();
                Array.Resize(ref bytes, 524);
                attr_list.AddAttribute(ProcessAttributes.ProcThreadAttributeSafeOpenPromptOriginClaim, bytes);
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

        internal ScopedDebugObject SetDebugObject()
        {
            if ((CreationFlags & (CreateProcessFlags.DebugProcess | CreateProcessFlags.DebugOnlyThisProcess)) == 0 || DebugObject == null)
            {
                return null;
            }
            return new ScopedDebugObject(DebugObject);
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

    /// <summary>
    /// Class representing a win32 process.
    /// </summary>
    public sealed class Win32Process : IDisposable
    {
        /// <summary>
        /// Create process with a token.
        /// </summary>
        /// <param name="token">The token to create the process with.</param>
        /// <param name="config">The process configuration.</param>
        /// <returns>The created win32 process.</returns>
        public static Win32Process CreateProcessAsUser(NtToken token, Win32ProcessConfig config)
        {
            using (var resources = new DisposableList<IDisposable>())
            {
                PROCESS_INFORMATION proc_info = new PROCESS_INFORMATION();
                STARTUPINFOEX start_info = config.ToStartupInfoEx(resources);
                SECURITY_ATTRIBUTES proc_attr = config.ProcessSecurityAttributes(resources);
                SECURITY_ATTRIBUTES thread_attr = config.ThreadSecurityAttributes(resources);

                using (var debug_object = config.SetDebugObject())
                {
                    if (Win32NativeMethods.CreateProcessAsUser(token.Handle, config.ApplicationName, config.CommandLine,
                            proc_attr, thread_attr, config.InheritHandles, config.CreationFlags
                            | CreateProcessFlags.ExtendedStartupInfoPresent, config.Environment,
                            config.CurrentDirectory, start_info, out proc_info))
                    {
                        return new Win32Process(proc_info, config.TerminateOnDispose);
                    }
                }

                if (config.NoTokenFallback)
                {
                    throw new SafeWin32Exception();
                }

                if (!Win32NativeMethods.CreateProcessWithTokenW(token.Handle, 0, config.ApplicationName, config.CommandLine,
                    config.CreationFlags, config.Environment, config.CurrentDirectory,
                    ref start_info.StartupInfo, out proc_info))
                {
                    throw new SafeWin32Exception();
                }

                return new Win32Process(proc_info, config.TerminateOnDispose);
            }
        }

        /// <summary>
        /// Create process with a token.
        /// </summary>
        /// <param name="token">The token to create the process with.</param>
        /// <param name="application_name">The path to the executable.</param>
        /// <param name="command_line">The process command line.</param>
        /// <param name="flags">Process creation flags.</param>
        /// <param name="desktop">The desktop name.</param>
        /// <returns>The created win32 process.</returns>
        public static Win32Process CreateProcessAsUser(NtToken token, string application_name, string command_line, CreateProcessFlags flags, string desktop)
        {
            Win32ProcessConfig config = new Win32ProcessConfig
            {
                ApplicationName = application_name,
                CommandLine = command_line,
                CreationFlags = flags,
                Desktop = desktop
            };

            return CreateProcessAsUser(token, config);
        }

        /// <summary>
        /// Create process with a token from a user logon.
        /// </summary>
        /// <param name="username">The username.</param>
        /// <param name="domain">The user's domain.</param>
        /// <param name="password">The user's password.</param>
        /// <param name="logon_flags">Logon flags.</param>
        /// <param name="config">The process configuration.</param>
        /// <returns>The created win32 process.</returns>
        public static Win32Process CreateProcessWithLogin(string username, string domain, string password, 
            CreateProcessLogonFlags logon_flags, Win32ProcessConfig config)
        {
            STARTUPINFO start_info = config.ToStartupInfo();
            PROCESS_INFORMATION proc_info = new PROCESS_INFORMATION();

            if (!Win32NativeMethods.CreateProcessWithLogonW(username, domain, password, logon_flags, 
                config.ApplicationName, config.CommandLine, config.CreationFlags,
                config.Environment, config.CurrentDirectory, ref start_info, out proc_info))
            {
                throw new SafeWin32Exception();
            }

            return new Win32Process(proc_info, config.TerminateOnDispose);
        }


        /// <summary>
        /// Create process with a token from a user logon.
        /// </summary>
        /// <param name="username">The username.</param>
        /// <param name="domain">The user's domain.</param>
        /// <param name="password">The user's password.</param>
        /// <param name="logon_flags">Logon flags.</param>
        /// <param name="application_name">The path to the executable.</param>
        /// <param name="command_line">The process command line.</param>
        /// <param name="flags">Process creation flags.</param>
        /// <param name="desktop">The desktop name.</param>
        /// <returns>The created win32 process.</returns>
        public static Win32Process CreateProcessWithLogin(string username, string domain, string password, CreateProcessLogonFlags logon_flags,
            string application_name, string command_line, CreateProcessFlags flags, string desktop)
        {
            Win32ProcessConfig config = new Win32ProcessConfig
            {
                ApplicationName = application_name,
                CommandLine = command_line,
                CreationFlags = flags,
                Desktop = desktop
            };
            return CreateProcessWithLogin(username, domain, password, logon_flags, config);
        }

        /// <summary>
        /// Create process.
        /// </summary>
        /// <param name="config">The process configuration.</param>
        /// <returns>The created win32 process.</returns>
        public static Win32Process CreateProcess(Win32ProcessConfig config)
        {
            if (config.Token != null)
            {
                return CreateProcessAsUser(config.Token, config);
            }

            PROCESS_INFORMATION proc_info = new PROCESS_INFORMATION();

            using (var resources = new DisposableList<IDisposable>())
            {
                SECURITY_ATTRIBUTES proc_attr = config.ProcessSecurityAttributes(resources);
                SECURITY_ATTRIBUTES thread_attr = config.ThreadSecurityAttributes(resources);

                using (var debug_object = config.SetDebugObject())
                {
                    if (!Win32NativeMethods.CreateProcess(config.ApplicationName, config.CommandLine, proc_attr, thread_attr, config.InheritHandles,
                            config.CreationFlags | CreateProcessFlags.ExtendedStartupInfoPresent,
                            config.Environment, config.CurrentDirectory, config.ToStartupInfoEx(resources), out proc_info))
                    {
                        throw new SafeWin32Exception();
                    }
                }

                return new Win32Process(proc_info, config.TerminateOnDispose);
            }
        }

        /// <summary>
        /// Create process.
        /// </summary>
        /// <param name="parent">Optional parent process.</param>
        /// <param name="application_name">The path to the executable.</param>
        /// <param name="command_line">The process command line.</param>
        /// <param name="flags">Process creation flags.</param>
        /// <param name="desktop">The desktop name.</param>
        /// <returns>The created win32 process.</returns>
        public static Win32Process CreateProcess(NtProcess parent, string application_name, string command_line, CreateProcessFlags flags, string desktop)
        {
            Win32ProcessConfig config = new Win32ProcessConfig
            {
                ParentProcess = parent,
                ApplicationName = application_name,
                CommandLine = command_line,
                CreationFlags = flags,
                Desktop = desktop
            };
            return CreateProcess(config);
        }

        /// <summary>
        /// Dispose the process.
        /// </summary>
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

        /// <summary>
        /// The handle to the process.
        /// </summary>
        public NtProcess Process { get; private set; }
        /// <summary>
        /// The handle to the initial thread.
        /// </summary>
        public NtThread Thread { get; private set; }
        /// <summary>
        /// The process ID of the process.
        /// </summary>
        public int Pid { get; private set; }
        /// <summary>
        /// The thread ID of the initial thread.
        /// </summary>
        public int Tid { get; private set; }
        /// <summary>
        /// True to terminate process when disposed.
        /// </summary>
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
