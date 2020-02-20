//  Copyright 2020 Google Inc. All Rights Reserved.
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
using System.Runtime.InteropServices;

namespace NtApiDotNet.Win32
{
    /// <summary>
    /// Flags for create process.
    /// </summary>
    [Flags]
    public enum CreateProcessFlags : uint
    {
        /// <summary>
        /// No flags.
        /// </summary>
        None = 0,
        /// <summary>
        /// Debug process.
        /// </summary>
        DebugProcess = 0x00000001,
        /// <summary>
        /// Debug only this process.
        /// </summary>
        DebugOnlyThisProcess = 0x00000002,
        /// <summary>
        /// Create suspended.
        /// </summary>
        Suspended = 0x00000004,
        /// <summary>
        /// Detach process.
        /// </summary>
        DetachedProcess = 0x00000008,
        /// <summary>
        /// Create a new console.
        /// </summary>
        NewConsole = 0x00000010,
        /// <summary>
        /// Normal priority class.
        /// </summary>
        NormalPriorityClass = 0x00000020,
        /// <summary>
        /// Idle priority class.
        /// </summary>
        IdlePriorityClass = 0x00000040,
        /// <summary>
        /// High priority class.
        /// </summary>
        HighPriorityClass = 0x00000080,
        /// <summary>
        /// Realtime priority class.
        /// </summary>
        RealtimePriorityClass = 0x00000100,
        /// <summary>
        /// Create a new process group.
        /// </summary>
        NewProcessGroup = 0x00000200,
        /// <summary>
        /// Create from a unicode environment.
        /// </summary>
        UnicodeEnvironment = 0x00000400,
        /// <summary>
        /// Create a separate WOW VDM.
        /// </summary>
        SeparateWowVdm = 0x00000800,
        /// <summary>
        /// Share the WOW VDM.
        /// </summary>
        SharedWowVdm = 0x00001000,
        /// <summary>
        /// Force DOS process.
        /// </summary>
        ForceDOS = 0x00002000,
        /// <summary>
        /// Below normal priority class.
        /// </summary>
        BelowNormalPriorityClass = 0x00004000,
        /// <summary>
        /// Above normal priority class.
        /// </summary>
        AboveNormalPriorityClass = 0x00008000,
        /// <summary>
        /// Inherit parent affinity.
        /// </summary>
        InheritParentAffinity = 0x00010000,
        /// <summary>
        /// Inherit caller priority (deprecated)
        /// </summary>
        InheritCallerPriority = 0x00020000,
        /// <summary>
        /// Create a protected process.
        /// </summary>
        ProtectedProcess = 0x00040000,
        /// <summary>
        /// Specify extended startup information is present.
        /// </summary>
        ExtendedStartupInfoPresent = 0x00080000,
        /// <summary>
        /// Process mode background begin.
        /// </summary>
        ModeBackgroundBegin = 0x00100000,
        /// <summary>
        /// Process mode background end.
        /// </summary>
        ModeBackgroundEnd = 0x00200000,
        /// <summary>
        /// Create a secure process.
        /// </summary>
        SecureProcess = 0x00400000,
        /// <summary>
        /// Breakaway from a job object.
        /// </summary>
        BreakawayFromJob = 0x01000000,
        /// <summary>
        /// Preserve code authz level.
        /// </summary>
        PreserveCodeAuthZLevel = 0x02000000,
        /// <summary>
        /// Default error mode.
        /// </summary>
        DefaultErrorMode = 0x04000000,
        /// <summary>
        /// No window.
        /// </summary>
        NoWindow = 0x08000000,
        /// <summary>
        /// Profile user.
        /// </summary>
        ProfileUser = 0x10000000,
        /// <summary>
        /// Profile kernel.
        /// </summary>
        ProfileKernel = 0x20000000,
        /// <summary>
        /// Profile server.
        /// </summary>
        ProfileServer = 0x40000000,
        /// <summary>
        /// Ignore system default.
        /// </summary>
        IgnoreSystemDefault = 0x80000000
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

    /// <summary>
    /// Flags for create thread.
    /// </summary>
    [Flags]
    public enum CreateThreadFlags : uint
    {
        /// <summary>
        /// No flags.
        /// </summary>
        None = 0,
        /// <summary>
        /// Create suspended.
        /// </summary>
        Suspended = 0x00000004,
        /// <summary>
        /// Stack size is a reservation.
        /// </summary>
        StackSizeParamIsAReservation = 0x00010000,
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

    /// <summary>
    /// Extended process flags.
    /// </summary>
    [Flags]
    public enum ProcessExtendedFlags
    {
        /// <summary>
        /// No flags.
        /// </summary>
        None = 0,
        /// <summary>
        /// Log elevation failure.
        /// </summary>
        LogElevationFailure = 0x1,
        /// <summary>
        /// Ignore elevation requirements.
        /// </summary>
        IgnoreElevationCheck = 0x2,
        /// <summary>
        /// Force job breakaway (needs TCB privilege).
        /// </summary>
        ForceBreakawayJob = 0x4,
    }

    class Win32ProcessAttributes
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
            ProcThreadAttributeExtendedFlags = 1,
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

        public static IntPtr ProcThreadAttributeParentProcess => GetValue(PROC_THREAD_ATTRIBUTE_NUM.ProcThreadAttributeParentProcess, false, true, false);

        public static IntPtr ProcThreadAttributeHandleList => GetValue(PROC_THREAD_ATTRIBUTE_NUM.ProcThreadAttributeHandleList, false, true, false);

        public static IntPtr ProcThreadAttributeMitigationPolicy => GetValue(PROC_THREAD_ATTRIBUTE_NUM.ProcThreadAttributeMitigationPolicy, false, true, false);

        public static IntPtr ProcThreadAttributeChildProcessPolicy => GetValue(PROC_THREAD_ATTRIBUTE_NUM.ProcThreadAttributeChildProcessPolicy, false, true, false);

        public static IntPtr ProcThreadAttributeWin32kFilter => GetValue(PROC_THREAD_ATTRIBUTE_NUM.ProcThreadAttributeWin32kFilter, false, true, false);

        public static IntPtr ProcThreadAttributeAllApplicationPackagesPolicy => GetValue(PROC_THREAD_ATTRIBUTE_NUM.ProcThreadAttributeAllApplicationPackagesPolicy, false, true, false);

        public static IntPtr ProcThreadAttribueJobList => GetValue(PROC_THREAD_ATTRIBUTE_NUM.ProcThreadAttributeJobList, false, true, false);

        public static IntPtr ProcThreadAttributeProtectionLevel => GetValue(PROC_THREAD_ATTRIBUTE_NUM.ProcThreadAttributeProtectionLevel, false, true, false);

        public static IntPtr ProcThreadAttributeSecurityCapabilities => GetValue(PROC_THREAD_ATTRIBUTE_NUM.ProcThreadAttributeSecurityCapabilities, false, true, false);

        public static IntPtr ProcThreadAttributeDesktopAppPolicy => GetValue(PROC_THREAD_ATTRIBUTE_NUM.ProcThreadAttributeDesktopAppPolicy, false, true, false);

        public static IntPtr ProcThreadAttributePackageName => GetValue(PROC_THREAD_ATTRIBUTE_NUM.ProcThreadAttributePackageName, false, true, false);

        public static IntPtr ProcThreadAttributePseudoConsole => GetValue(PROC_THREAD_ATTRIBUTE_NUM.ProcThreadAttributePseudoConsole, false, true, false);

        public static IntPtr ProcThreadAttributeBnoIsolation => GetValue(PROC_THREAD_ATTRIBUTE_NUM.ProcThreadAttributeBnoIsolation, false, true, false);

        public static IntPtr ProcThreadAttributeSafeOpenPromptOriginClaim => GetValue(PROC_THREAD_ATTRIBUTE_NUM.ProcThreadAttributeSafeOpenPromptOriginClaim, false, true, false);

        public static IntPtr ProcThreadAttributeExtendedFlags => GetValue(PROC_THREAD_ATTRIBUTE_NUM.ProcThreadAttributeExtendedFlags, false, true, true);
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
        ModuleTamperingProtectionNoInherit = (0x00000003UL << 12),
        RestrictBranchPredictionAlwaysOn = (0x00000001UL << 16),
        RestrictBranchPredictionAlwaysOff  = (0x00000002UL << 16),
        AllowDowngradeDynamicCodePolicyAlwaysOn = (0x00000001UL << 20),
        AllowDowngradeDynamicCodePolicyAlwaysOff = (0x00000002UL << 20),
        SpeculativeStoreBypassDisableAlwaysOn = (0x00000001UL << 24),
        SpeculativeStoreBypassDisableAlwaysOff = (0x00000002UL << 24),
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
}
