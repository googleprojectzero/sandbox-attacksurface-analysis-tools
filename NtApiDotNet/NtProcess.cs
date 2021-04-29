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

using NtApiDotNet.Win32;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;

namespace NtApiDotNet
{
    /// <summary>
    /// Class representing a NT Process object.
    /// </summary>
    [NtType("Process")]
    public class NtProcess : NtObjectWithDuplicateAndInfo<NtProcess, ProcessAccessRights, ProcessInformationClass, ProcessInformationClass>
    {
        #region Private Members
        private int? _pid;
        private ProcessExtendedBasicInformation _extended_info;
        private bool? _wow64;

        private ProcessExtendedBasicInformation GetExtendedBasicInfo(bool get_cached)
        {
            if (_extended_info == null || !get_cached)
            {
                if (!IsAccessGranted(ProcessAccessRights.QueryLimitedInformation)
                    && !IsAccessGranted(ProcessAccessRights.QueryInformation))
                {
                    // If we don't have query try and duplicate.
                    using (var dup_process = Duplicate(ProcessAccessRights.QueryLimitedInformation, false))
                    {
                        if (dup_process.IsSuccess)
                            return dup_process.Result.GetExtendedBasicInfo(false);
                        _extended_info = new ProcessExtendedBasicInformation();
                    }
                }
                else
                {
                    using (var buffer = Query(ProcessInformationClass.ProcessBasicInformation, new ProcessExtendedBasicInformation(), false))
                    {
                        if (buffer.IsSuccess)
                        {
                            _extended_info = buffer.Result;
                        }
                        else
                        {
                            ProcessExtendedBasicInformation result = new ProcessExtendedBasicInformation
                            {
                                BasicInfo = Query<ProcessBasicInformation>(ProcessInformationClass.ProcessBasicInformation)
                            };
                            _extended_info = result;
                        }
                    }
                }
            }

            return _extended_info;
        }

        private ProcessBasicInformation GetBasicInfo()
        {
            return GetExtendedBasicInfo(true).BasicInfo;
        }

        private static Enum ConvertPolicyToEnum(ProcessMitigationPolicy policy, int value)
        {
            switch (policy)
            {
                case ProcessMitigationPolicy.ImageLoad:
                    return (ProcessMitigationImageLoadPolicy)value;
                case ProcessMitigationPolicy.Signature:
                    return (ProcessMitigationBinarySignaturePolicy)value;
                case ProcessMitigationPolicy.ControlFlowGuard:
                    return (ProcessMitigationControlFlowGuardPolicy)value;
                case ProcessMitigationPolicy.DynamicCode:
                    return (ProcessMitigationDynamicCodePolicy)value;
                case ProcessMitigationPolicy.ExtensionPointDisable:
                    return (ProcessMitigationExtensionPointDisablePolicy)value;
                case ProcessMitigationPolicy.FontDisable:
                    return (ProcessMitigationFontDisablePolicy)value;
                case ProcessMitigationPolicy.StrictHandleCheck:
                    return (ProcessMitigationStrictHandleCheckPolicy)value;
                case ProcessMitigationPolicy.SystemCallDisable:
                    return (ProcessMitigationSystemCallDisablePolicy)value;
                case ProcessMitigationPolicy.ChildProcess:
                    return (ProcessMitigationChildProcessPolicy)value;
                case ProcessMitigationPolicy.PayloadRestriction:
                    return (ProcessMitigationPayloadRestrictionPolicy)value;
                case ProcessMitigationPolicy.SystemCallFilter:
                    return (ProcessMitigationSystemCallFilterPolicy)value;
                case ProcessMitigationPolicy.SideChannelIsolation:
                    return (ProcessMitigationSideChannelIsolationPolicy)value;
                case ProcessMitigationPolicy.ASLR:
                    return (ProcessMitigationAslrPolicy)value;
                case ProcessMitigationPolicy.UserShadowStack:
                    return (ProcessMitigationUserShadowStack)value;
                default:
                    return (ProcessMitigationUnknownPolicy)value;
            }
        }

        private T QueryToken<T>(TokenAccessRights desired_access, Func<NtToken, T> callback, T default_value)
        {
            return NtToken.OpenProcessToken(this, desired_access, false).RunAndDispose(callback, default_value);
        }

        private T QueryToken<T>(Func<NtToken, T> callback, T default_value)
        {
            return QueryToken(TokenAccessRights.Query, callback, default_value);
        }

        private T QueryToken<T>(Func<NtToken, T> callback)
        {
            return QueryToken(TokenAccessRights.Query, callback, default);
        }

        private static NtProcessCreateResult Create(NtProcessCreateConfig config, string image_path, bool fork, bool throw_on_error)
        {
            using (var dispose = new DisposableList())
            {
                var process_params = SafeProcessParametersBuffer.Null;
                if (!fork)
                {
                    var result = dispose.AddResource(SafeProcessParametersBuffer.Create(config.ConfigImagePath ?? image_path,
                        config.DllPath, config.CurrentDirectory, config.CommandLine, config.Environment,
                        config.WindowTitle, config.DesktopInfo, config.ShellInfo, config.RuntimeData,
                        CreateProcessParametersFlags.Normalize, throw_on_error));
                    if (!result.IsSuccess)
                        return new NtProcessCreateResult(result.Status);
                    process_params = result.Result;
                    if (config.ProcessParametersCallback != null)
                    {
                        process_params = config.ProcessParametersCallback(process_params, dispose);
                    }
                    if (!string.IsNullOrWhiteSpace(config.RedirectionDllName)
                        && NtObjectUtils.SupportedVersion >= SupportedVersion.Windows10_19H1)
                    {
                        var str = dispose.AddResource(new UnicodeStringAllocated(config.RedirectionDllName));
                        IntPtr offset = Marshal.OffsetOf(typeof(RtlUserProcessParameters), "RedirectionDllName");
                        process_params.Write((ulong)offset.ToInt32(), str.String);
                    }
                }

                ProcessCreateInfo create_info = dispose.AddResource(new ProcessCreateInfo());
                if (!fork)
                {
                    dispose.Add(ProcessAttribute.ImageName(image_path));
                }

                SafeStructureInOutBuffer<SectionImageInformation> image_info = new SafeStructureInOutBuffer<SectionImageInformation>();
                dispose.Add(ProcessAttribute.ImageInfo(image_info));
                SafeStructureInOutBuffer<ClientId> client_id = new SafeStructureInOutBuffer<ClientId>();
                dispose.Add(ProcessAttribute.ClientId(client_id));

                if (config.ParentProcess != null)
                {
                    dispose.Add(ProcessAttribute.ParentProcess(config.ParentProcess.Handle));
                }

                if (config.DebugObject != null)
                {
                    dispose.Add(ProcessAttribute.DebugPort(config.DebugObject.Handle));
                }

                if (config.ChildProcessMitigations != ChildProcessMitigationFlags.None)
                {
                    dispose.Add(ProcessAttribute.ChildProcess(config.ChildProcessMitigations));
                }

                if (config.Token != null)
                {
                    dispose.Add(ProcessAttribute.Token(config.Token.Handle));
                }

                if (config.ProtectionLevel.Level != 0)
                {
                    dispose.Add(ProcessAttribute.ProtectionLevel(config.ProtectionLevel));
                }

                if (config.Secure)
                {
                    var trustlet_config = config.TrustletConfig ?? NtProcessTrustletConfig.CreateFromFile(image_path, false).GetResultOrDefault();
                    if (trustlet_config == null)
                        throw new ArgumentException("Couldn't extract trustlet configuration from image file.");
                    dispose.Add(ProcessAttribute.SecureProcess(trustlet_config));
                }

                if (config.InheritHandleList.Count > 0)
                {
                    dispose.Add(ProcessAttribute.HandleList(config.InheritHandleList.Select(o => o.Handle)));
                }

                var attr_list = dispose.AddResource(ProcessAttributeList.Create(dispose.OfType<ProcessAttribute>().Concat(config.AdditionalAttributes)));
                create_info.Data.InitFlags = config.InitFlags;
                if (config.CaptureAdditionalInformation)
                {
                    create_info.Data.InitFlags |= ProcessCreateInitFlag.WriteOutputOnExit;
                }
                create_info.Data.ProhibitedImageCharacteristics = config.ProhibitedImageCharacteristics;
                create_info.Data.AdditionalFileAccess = config.AdditionalFileAccess;

                var proc_attr = dispose.AddResource(new ObjectAttributes(null, AttributeFlags.None,
                        SafeKernelObjectHandle.Null, null, config.ProcessSecurityDescriptor));
                var thread_attr = dispose.AddResource(new ObjectAttributes(null, AttributeFlags.None,
                        SafeKernelObjectHandle.Null, null, config.ThreadSecurityDescriptor));

                ProcessCreateFlags process_flags = config.ProcessFlags;
                if (fork)
                {
                    process_flags |= ProcessCreateFlags.InheritFromParent;
                }

                NtStatus status = NtSystemCalls.NtCreateUserProcess(
                    out SafeKernelObjectHandle process_handle, out SafeKernelObjectHandle thread_handle,
                    config.ProcessDesiredAccess, config.ThreadDesiredAccess,
                    proc_attr, thread_attr, config.ProcessFlags,
                    config.ThreadFlags, process_params.DangerousGetHandle(), create_info, attr_list).ToNtException(throw_on_error);
                if (create_info.State == ProcessCreateState.Success)
                {
                    return new NtProcessCreateResult(status, process_handle, thread_handle,
                        create_info.Data, image_info.Result, client_id.Result, config.TerminateOnDispose);
                }
                else
                {
                    return new NtProcessCreateResult(status, create_info.Data, create_info.State);
                }
            }
        }

        #endregion

        #region Constructors

        internal NtProcess(SafeKernelObjectHandle handle) : base(handle)
        {
        }

        internal sealed class NtTypeFactoryImpl : NtTypeFactoryImplBase
        {
            public NtTypeFactoryImpl() : base(false, MandatoryLabelPolicy.NoWriteUp | MandatoryLabelPolicy.NoReadUp)
            {
            }
        }

        #endregion

        #region Static Methods

        /// <summary>
        /// Gets all accessible processes on the system.
        /// </summary>
        /// <param name="desired_access">The access desired for each process.</param>
        /// <returns>The list of accessible processes.</returns>
        public static IEnumerable<NtProcess> GetProcesses(ProcessAccessRights desired_access)
        {
            return GetProcesses(desired_access, false);
        }

        /// <summary>
        /// Gets all accessible processes on the system.
        /// </summary>
        /// <param name="desired_access">The access desired for each process.</param>
        /// <param name="from_system_info">True to get processes from system information rather than NtGetNextProcess</param>
        /// <returns>The list of accessible processes.</returns>
        public static IEnumerable<NtProcess> GetProcesses(ProcessAccessRights desired_access, bool from_system_info)
        {
            using (var processes = new DisposableList<NtProcess>())
            {
                if (from_system_info)
                {
                    processes.AddRange(NtSystemInfo.GetProcessInformation().Select(p => Open(p.ProcessId, desired_access, false)).SelectValidResults());
                }
                else
                {
                    NtProcess process = NtProcess.GetFirstProcess(desired_access);
                    while (process != null)
                    {
                        processes.Add(process);
                        process = process.GetNextProcess(desired_access);
                    }
                }
                return processes.ToArrayAndClear();
            }
        }

        /// <summary>
        /// Gets all accessible processes on the system in a particular session.
        /// </summary>
        /// <param name="session_id">The session ID.</param>
        /// <param name="desired_access">The access desired for each process.</param>
        /// <returns>The list of accessible processes.</returns>
        public static IEnumerable<NtProcess> GetSessionProcesses(int session_id, ProcessAccessRights desired_access)
        {
            return NtSystemInfo.GetProcessInformation().Where(p => p.SessionId == session_id)
                .Select(p => Open(p.ProcessId, desired_access, false))
                .SelectValidResults().ToArray();
        }

        /// <summary>
        /// Gets all accessible processes on the system in the current session session.
        /// </summary>
        /// <param name="desired_access">The access desired for each process.</param>
        /// <returns>The list of accessible processes.</returns>
        public static IEnumerable<NtProcess> GetSessionProcesses(ProcessAccessRights desired_access)
        {
            return GetSessionProcesses(Current.SessionId, desired_access);
        }

        /// <summary>
        /// Get first accessible process (used in combination with GetNextProcess)
        /// </summary>
        /// <param name="desired_access">The access required for the process.</param>
        /// <returns>The accessible process, or null if one couldn't be opened.</returns>
        public static NtProcess GetFirstProcess(ProcessAccessRights desired_access)
        {
            NtStatus status = NtSystemCalls.NtGetNextProcess(SafeKernelObjectHandle.Null, desired_access,
                AttributeFlags.None, 0, out SafeKernelObjectHandle new_handle);
            if (status == NtStatus.STATUS_SUCCESS)
            {
                return new NtProcess(new_handle);
            }
            return null;
        }

        /// <summary>
        /// Open a process
        /// </summary>
        /// <param name="pid">The process ID to open</param>
        /// <param name="tid">Optional thread ID to verify the correct process is opened.</param>
        /// <param name="desired_access">The desired access for the handle</param>
        /// <param name="throw_on_error">True to throw an exception on error.</param>
        /// <returns>The NT status code and object result.</returns>
        public static NtResult<NtProcess> Open(int pid, int tid, ProcessAccessRights desired_access, bool throw_on_error)
        {
            ClientId client_id = new ClientId
            {
                UniqueProcess = new IntPtr(pid),
                UniqueThread = new IntPtr(tid)
            };
            return NtSystemCalls.NtOpenProcess(out SafeKernelObjectHandle process, desired_access, new ObjectAttributes(), client_id)
                .CreateResult(throw_on_error, () => new NtProcess(process) { _pid = pid });
        }

        /// <summary>
        /// Open a process
        /// </summary>
        /// <param name="pid">The process ID to open</param>
        /// <param name="desired_access">The desired access for the handle</param>
        /// <param name="throw_on_error">True to throw an exception on error.</param>
        /// <returns>The NT status code and object result.</returns>
        public static NtResult<NtProcess> Open(int pid, ProcessAccessRights desired_access, bool throw_on_error)
        {
            return Open(pid, 0, desired_access, throw_on_error);
        }

        /// <summary>
        /// Open a process
        /// </summary>
        /// <param name="pid">The process ID to open</param>
        /// <param name="desired_access">The desired access for the handle</param>
        /// <returns>The opened process</returns>
        public static NtProcess Open(int pid, ProcessAccessRights desired_access)
        {
            return Open(pid, desired_access, true).Result;
        }

        /// <summary>
        /// Open a process
        /// </summary>
        /// <param name="pid">The process ID to open</param>
        /// <param name="tid">Optional thread ID to verify the correct process is opened.</param>
        /// <param name="desired_access">The desired access for the handle</param>
        /// <returns>The opened process.</returns>
        public static NtProcess Open(int pid, int tid, ProcessAccessRights desired_access)
        {
            return Open(pid, tid, desired_access, true).Result;
        }

        /// <summary>
        /// Create a new process
        /// </summary>
        /// <param name="object_attributes">Optional object attributes.</param>
        /// <param name="desired_access">Desired access for the new process.</param>
        /// <param name="parent_process">The parent process</param>
        /// <param name="flags">Creation flags</param>
        /// <param name="section_handle">Handle to the executable image section</param>
        /// <param name="debug_port">Debug port for the new process.</param>
        /// <param name="token">Access token for the new process.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The created process</returns>
        [Obsolete("Use Create")]
        public static NtResult<NtProcess> CreateProcessEx(ObjectAttributes object_attributes, ProcessAccessRights desired_access,
            NtProcess parent_process, ProcessCreateFlags flags, NtSection section_handle, NtDebug debug_port, NtToken token, bool throw_on_error)
        {
            return Create(object_attributes, desired_access, parent_process, flags, section_handle, debug_port, token, throw_on_error);
        }

        /// <summary>
        /// Create a new process
        /// </summary>
        /// <param name="desired_access">Desired access for the new process.</param>
        /// <param name="object_attributes">Optional object attributes.</param>
        /// <param name="parent_process">The parent process</param>
        /// <param name="flags">Creation flags</param>
        /// <param name="section_handle">Handle to the executable image section</param>
        /// <param name="debug_port">Debug port for the new process.</param>
        /// <param name="token">Access token for the new process.</param>
        /// <returns>The created process</returns>
        [Obsolete("Use Create")]
        public static NtProcess CreateProcessEx(ObjectAttributes object_attributes, ProcessAccessRights desired_access,
            NtProcess parent_process, ProcessCreateFlags flags, NtSection section_handle, NtDebug debug_port, NtToken token)
        {
            return CreateProcessEx(object_attributes, desired_access, parent_process, flags, section_handle, debug_port, token, true).Result;
        }

        /// <summary>
        /// Create a new process
        /// </summary>
        /// <param name="parent_process">The parent process</param>
        /// <param name="flags">Creation flags</param>
        /// <param name="section_handle">Handle to the executable image section</param>
        /// <param name="token">Access token for the new process.</param>
        /// <returns>The created process</returns>
        [Obsolete("Use Create")]
        public static NtProcess CreateProcessEx(NtProcess parent_process, ProcessCreateFlags flags, NtSection section_handle, NtToken token)
        {
            return CreateProcessEx(null, ProcessAccessRights.MaximumAllowed, parent_process, flags, section_handle, null, token);
        }

        /// <summary>
        /// Create a new process
        /// </summary>
        /// <param name="parent_process">The parent process</param>
        /// <param name="flags">Creation flags</param>
        /// <param name="section_handle">Handle to the executable image section</param>
        /// <returns>The created process</returns>
        [Obsolete("Use Create")]
        public static NtProcess CreateProcessEx(NtProcess parent_process, ProcessCreateFlags flags, NtSection section_handle)
        {
            return CreateProcessEx(parent_process, flags, section_handle, null);
        }

        /// <summary>
        /// Create a new process
        /// </summary>
        /// <param name="section_handle">Handle to the executable image section</param>
        /// <param name="token">Access token for the new process.</param>
        /// <returns>The created process</returns>
        [Obsolete("Use Create")]
        public static NtProcess CreateProcessEx(NtSection section_handle, NtToken token)
        {
            return CreateProcessEx(null, ProcessCreateFlags.None, section_handle, token);
        }

        /// <summary>
        /// Create a new process
        /// </summary>
        /// <param name="section_handle">Handle to the executable image section</param>
        /// <returns>The created process</returns>
        [Obsolete("Use Create")]
        public static NtProcess CreateProcessEx(NtSection section_handle)
        {
            return CreateProcessEx(section_handle, null);
        }

        /// <summary>
        /// Create a new process
        /// </summary>
        /// <param name="object_attributes">Optional object attributes.</param>
        /// <param name="desired_access">Desired access for the new process.</param>
        /// <param name="parent_process">The parent process</param>
        /// <param name="flags">Creation flags</param>
        /// <param name="section_handle">Handle to the executable image section</param>
        /// <param name="debug_port">Debug port for the new process.</param>
        /// <param name="token">Access token for the new process.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The created process</returns>
        /// <remarks>This uses NtCreateProcessEx rather than NtCreateUserProcess</remarks>
        public static NtResult<NtProcess> Create(ObjectAttributes object_attributes, ProcessAccessRights desired_access,
            NtProcess parent_process, ProcessCreateFlags flags, NtSection section_handle, NtDebug debug_port, NtToken token, bool throw_on_error)
        {
            return NtSystemCalls.NtCreateProcessEx(out SafeKernelObjectHandle process, desired_access,
                object_attributes, parent_process?.Handle ?? Current.Handle, flags, section_handle.GetHandle(), debug_port.GetHandle(),
                token.GetHandle(), 0).CreateResult(throw_on_error, () => new NtProcess(process));
        }

        /// <summary>
        /// Create a new process
        /// </summary>
        /// <param name="desired_access">Desired access for the new process.</param>
        /// <param name="object_attributes">Optional object attributes.</param>
        /// <param name="parent_process">The parent process</param>
        /// <param name="flags">Creation flags</param>
        /// <param name="section_handle">Handle to the executable image section</param>
        /// <param name="debug_port">Debug port for the new process.</param>
        /// <param name="token">Access token for the new process.</param>
        /// <returns>The created process</returns>
        public static NtProcess Create(ObjectAttributes object_attributes, ProcessAccessRights desired_access,
            NtProcess parent_process, ProcessCreateFlags flags, NtSection section_handle, NtDebug debug_port, NtToken token)
        {
            return Create(object_attributes, desired_access, parent_process, flags, section_handle, debug_port, token, true).Result;
        }

        /// <summary>
        /// Create a new user process.
        /// </summary>
        /// <param name="config">The process configuration.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The result of the process creation</returns>
        public static NtProcessCreateResult Create(NtProcessCreateConfig config, bool throw_on_error)
        {
            string image_path = config.ImagePath ?? config.ConfigImagePath;
            if (image_path == null)
                throw new ArgumentNullException("image_path");

            return Create(config, image_path, false, throw_on_error);
        }



        /// <summary>
        /// Create a new user process.
        /// </summary>
        /// <param name="config">The process configuration.</param>
        /// <returns>The result of the process creation</returns>
        public static NtProcessCreateResult Create(NtProcessCreateConfig config)
        {
            return Create(config, true);
        }

        /// <summary>
        /// Fork a process.
        /// </summary>
        /// <param name="config">The process configuration.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The new forked process result</returns>
        /// <remarks>This uses NtCreateUserProcess.</remarks>
        public static NtProcessCreateResult Fork(NtProcessCreateConfig config, bool throw_on_error)
        {
            return Create(config, string.Empty, true, throw_on_error);
        }

        /// <summary>
        /// Fork a process.
        /// </summary>
        /// <param name="config">The process configuration.</param>
        /// <returns>The new forked process result</returns>
        /// <remarks>This uses NtCreateUserProcess.</remarks>
        public static NtProcessCreateResult Fork(NtProcessCreateConfig config)
        {
            return Fork(config, true);
        }

        /// <summary>
        /// Open an actual handle to the current process rather than the pseudo one used for Current
        /// </summary>
        /// <returns>The process object</returns>
        public static NtProcess OpenCurrent()
        {
            return Current.Duplicate();
        }

        /// <summary>
        /// Test whether a process can access another protected process.
        /// </summary>
        /// <param name="current">The current process.</param>
        /// <param name="target">The target process.</param>
        /// <returns>True if the process can be accessed.</returns>
        public static bool TestProtectedAccess(NtProcess current, NtProcess target)
        {
            return NtRtl.RtlTestProtectedAccess(current.Protection.Level, target.Protection.Level);
        }

        #endregion

        #region Public Methods

        /// <summary>
        /// Reopen object with different access rights.
        /// </summary>
        /// <param name="desired_access">The desired access.</param>
        /// <param name="attributes">Additional attributes for open.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The reopened object.</returns>
        public override NtResult<NtProcess> ReOpen(ProcessAccessRights desired_access, AttributeFlags attributes, bool throw_on_error)
        {
            return Open(ProcessId, desired_access, throw_on_error);
        }

        /// <summary>
        /// Get next accessible process (used in combination with GetFirstProcess)
        /// </summary>
        /// <param name="desired_access">The access required for the process.</param>
        /// <returns>The accessible process, or null if one couldn't be opened.</returns>
        public NtProcess GetNextProcess(ProcessAccessRights desired_access)
        {
            NtStatus status = NtSystemCalls.NtGetNextProcess(Handle, desired_access, AttributeFlags.None, 
                GetNextProcessFlags.None, out SafeKernelObjectHandle new_handle);
            if (status == NtStatus.STATUS_SUCCESS)
            {
                return new NtProcess(new_handle);
            }
            return null;
        }

        /// <summary>
        /// Get previous accessible process (used in combination with GetFirstProcess)
        /// </summary>
        /// <param name="desired_access">The access required for the process.</param>
        /// <returns>The accessible process, or null if one couldn't be opened.</returns>
        public NtProcess GetPreviousProcess(ProcessAccessRights desired_access)
        {
            NtStatus status = NtSystemCalls.NtGetNextProcess(Handle, desired_access, AttributeFlags.None,
                GetNextProcessFlags.PreviousProcess, out SafeKernelObjectHandle new_handle);
            if (status == NtStatus.STATUS_SUCCESS)
            {
                return new NtProcess(new_handle);
            }
            return null;
        }

        /// <summary>
        /// Get previous accessible process (used in combination with GetFirstProcess)
        /// </summary>
        /// <returns>The accessible process, or null if one couldn't be opened.</returns>
        public NtProcess GetPreviousProcess()
        {
            return GetPreviousProcess(ProcessAccessRights.MaximumAllowed);
        }

        /// <summary>
        /// Get first accessible thread for process.
        /// </summary>
        /// <param name="desired_access">The desired access for the thread.</param>
        /// <returns>The first thread object, or null if not accessible threads.</returns>
        public NtThread GetFirstThread(ThreadAccessRights desired_access)
        {
            return NtThread.GetFirstThread(this, desired_access);
        }

        /// <summary>
        /// Get first accessible thread for process.
        /// </summary>
        /// <returns>The first thread object, or null if not accessible threads.</returns>
        public NtThread GetFirstThread()
        {
            return GetFirstThread(ThreadAccessRights.MaximumAllowed);
        }

        /// <summary>
        /// Get accessible threads for a process.
        /// </summary>
        /// <param name="desired_access">The desired access for the threads</param>
        /// <returns>The list of threads</returns>
        public IEnumerable<NtThread> GetThreads(ThreadAccessRights desired_access)
        {
            List<NtThread> handles = new List<NtThread>();
            if (IsAccessGranted(ProcessAccessRights.QueryInformation))
            {
                SafeKernelObjectHandle current_handle = new SafeKernelObjectHandle(IntPtr.Zero, false);
                NtStatus status = NtSystemCalls.NtGetNextThread(Handle, current_handle, desired_access, AttributeFlags.None, 0, out current_handle);
                while (status == NtStatus.STATUS_SUCCESS)
                {
                    handles.Add(new NtThread(current_handle));
                    status = NtSystemCalls.NtGetNextThread(Handle, current_handle, desired_access, AttributeFlags.None, 0, out current_handle);
                }
            }
            else
            {
                handles.AddRange(NtSystemInfo.GetThreadInformation(ProcessId).Select(t =>
                            NtThread.Open(t.ThreadId, desired_access, false)).SelectValidResults());
            }
            return handles;
        }

        /// <summary>
        /// Get accessible threads for a process.
        /// </summary>
        /// <returns>The list of threads</returns>
        public IEnumerable<NtThread> GetThreads()
        {
            return GetThreads(ThreadAccessRights.MaximumAllowed);
        }

        /// <summary>
        /// Read a partial PEB from the process.
        /// </summary>
        /// <returns>The read PEB structure.</returns>
        public IPeb GetPeb()
        {
            if (Wow64)
            {
                return NtVirtualMemory.ReadMemory<PartialPeb32>(Handle, PebAddress32.ToInt64());
            }
            return NtVirtualMemory.ReadMemory<PartialPeb>(Handle, PebAddress.ToInt64());
        }

        /// <summary>
        /// Create a new process
        /// </summary>
        /// <param name="flags">Creation flags</param>
        /// <param name="section_handle">Handle to the executable image section</param>
        /// <returns>The created process</returns>
        /// <remarks>This uses NtCreateProcessEx rather than NtCreateUserProcess</remarks>
        public NtProcess Create(ProcessCreateFlags flags, NtSection section_handle)
        {
            return Create(null, ProcessAccessRights.MaximumAllowed, flags, section_handle, null, null);
        }

        /// <summary>
        /// Create a new process
        /// </summary>
        /// <param name="object_attributes">Optional object attributes.</param>
        /// <param name="desired_access">Desired access for the new process.</param>
        /// <param name="flags">Creation flags</param>
        /// <param name="section_handle">Handle to the executable image section</param>
        /// <param name="debug_port">Debug port for the new process.</param>
        /// <param name="token">Access token for the new process.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The created process</returns>
        /// <remarks>This uses NtCreateProcessEx rather than NtCreateUserProcess</remarks>
        public NtResult<NtProcess> Create(ObjectAttributes object_attributes, ProcessAccessRights desired_access,
            ProcessCreateFlags flags, NtSection section_handle, NtDebug debug_port, NtToken token, bool throw_on_error)
        {
            return Create(object_attributes, desired_access, this, flags, section_handle, debug_port, token, throw_on_error);
        }

        /// <summary>
        /// Create a new process
        /// </summary>
        /// <param name="object_attributes">Optional object attributes.</param>
        /// <param name="desired_access">Desired access for the new process.</param>
        /// <param name="flags">Creation flags</param>
        /// <param name="section_handle">Handle to the executable image section</param>
        /// <param name="debug_port">Debug port for the new process.</param>
        /// <param name="token">Access token for the new process.</param>
        /// <returns>The created process</returns>
        /// <remarks>This uses NtCreateProcessEx rather than NtCreateUserProcess</remarks>
        public NtProcess Create(ObjectAttributes object_attributes, ProcessAccessRights desired_access,
            ProcessCreateFlags flags, NtSection section_handle, NtDebug debug_port, NtToken token)
        {
            return Create(object_attributes, desired_access, flags, section_handle, debug_port, token, true).Result;
        }

        /// <summary>
        /// Terminate the process
        /// </summary>
        /// <param name="exitcode">The exit code for the termination</param>
        public void Terminate(int exitcode)
        {
            Terminate((NtStatus)exitcode);
        }

        /// <summary>
        /// Terminate the process
        /// </summary>
        /// <param name="exitcode">The exit code for the termination</param>
        public void Terminate(NtStatus exitcode)
        {
            Terminate(exitcode, true);
        }

        /// <summary>
        /// Terminate the process
        /// </summary>
        /// <param name="exitcode">The exit code for the termination</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public NtStatus Terminate(NtStatus exitcode, bool throw_on_error)
        {
            return NtSystemCalls.NtTerminateProcess(Handle, exitcode).ToNtException(throw_on_error);
        }

        /// <summary>
        /// Get process image file path
        /// </summary>
        /// <param name="native">True to return the native image path, false for a Win32 style path</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The process image file path</returns>
        public NtResult<string> GetImageFilePath(bool native, bool throw_on_error)
        {
            ProcessInformationClass info_class = native ? ProcessInformationClass.ProcessImageFileName : ProcessInformationClass.ProcessImageFileNameWin32;

            using (var result = QueryBuffer(info_class, new UnicodeStringOut(), throw_on_error))
            {
                return result.Map(s => s.Result.ToString());
            }
        }

        /// <summary>
        /// Get process image file path
        /// </summary>
        /// <param name="native">True to return the native image path, false for a Win32 style path</param>
        /// <returns>The process image file path</returns>
        public string GetImageFilePath(bool native)
        {
            return GetImageFilePath(native, true).Result;
        }

        /// <summary>
        /// Get a mitigation policy raw value
        /// </summary>
        /// <param name="policy">The policy to get</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The raw policy value</returns>
        public NtResult<int> GetRawMitigationPolicy(ProcessMitigationPolicy policy, bool throw_on_error)
        {
            switch (policy)
            {
                case ProcessMitigationPolicy.DEP:
                case ProcessMitigationPolicy.MitigationOptionsMask:
                    throw new ArgumentException("Invalid mitigation policy");
            }

            MitigationPolicy p = new MitigationPolicy
            {
                Policy = policy
            };

            return Query(ProcessInformationClass.ProcessMitigationPolicy, p, throw_on_error).Map(r => r.Result);
        }

        /// <summary>
        /// Get a mitigation policy raw value
        /// </summary>
        /// <param name="policy">The policy to get</param>
        /// <returns>The raw policy value</returns>
        public int GetRawMitigationPolicy(ProcessMitigationPolicy policy)
        {
            switch (policy)
            {
                case ProcessMitigationPolicy.DEP:
                case ProcessMitigationPolicy.MitigationOptionsMask:
                    throw new ArgumentException("Invalid mitigation policy");
            }

            MitigationPolicy p = new MitigationPolicy
            {
                Policy = policy
            };

            var result = GetRawMitigationPolicy(policy, false);
            switch (result.Status)
            {
                case NtStatus.STATUS_INVALID_PARAMETER:
                case NtStatus.STATUS_NOT_SUPPORTED:
                case NtStatus.STATUS_PROCESS_IS_TERMINATING:
                    return 0;
            }

            return result.GetResultOrThrow();
        }

        /// <summary>
        /// Get a mitigation policy as an enumeration.
        /// </summary>
        /// <param name="policy">The policy to get.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The mitigation policy value</returns>
        public NtResult<Enum> GetMitigationPolicy(ProcessMitigationPolicy policy, bool throw_on_error)
        {
            return GetRawMitigationPolicy(policy, throw_on_error).Map(i => ConvertPolicyToEnum(policy, i));
        }

        /// <summary>
        /// Get a mitigation policy as an enumeration.
        /// </summary>
        /// <param name="policy">The policy to get.</param>
        /// <returns>The mitigation policy value</returns>
        public Enum GetMitigationPolicy(ProcessMitigationPolicy policy)
        {
            return GetMitigationPolicy(policy, true).Result;
        }

        /// <summary>
        /// Get a mitigation policy raw value
        /// </summary>
        /// <param name="policy">The policy to get</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The raw policy value</returns>
        [Obsolete("Use GetRawMitigationPolicy or GetMitigationPolicy")]
        public NtResult<int> GetProcessMitigationPolicy(ProcessMitigationPolicy policy, bool throw_on_error)
        {
            return GetRawMitigationPolicy(policy, throw_on_error);
        }

        /// <summary>
        /// Get a mitigation policy raw value
        /// </summary>
        /// <param name="policy">The policy to get</param>
        /// <returns>The raw policy value</returns>
        [Obsolete("Use GetRawMitigationPolicy or GetMitigationPolicy")]
        public int GetProcessMitigationPolicy(ProcessMitigationPolicy policy)
        {
            return GetRawMitigationPolicy(policy);
        }

        /// <summary>
        /// Set a mitigation policy raw value
        /// </summary>
        /// <param name="policy">The policy to set</param>
        /// <param name="value">The value to set</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public NtStatus SetRawMitigationPolicy(ProcessMitigationPolicy policy, int value, bool throw_on_error)
        {
            switch (policy)
            {
                case ProcessMitigationPolicy.DEP:
                case ProcessMitigationPolicy.MitigationOptionsMask:
                    throw new ArgumentException("Invalid mitigation policy");
            }

            MitigationPolicy p = new MitigationPolicy()
            {
                Policy = policy,
                Result = value
            };

            return Set(ProcessInformationClass.ProcessMitigationPolicy, p, throw_on_error);
        }

        /// <summary>
        /// Set a mitigation policy raw value
        /// </summary>
        /// <param name="policy">The policy to set</param>
        /// <param name="value">The value to set</param>
        public void SetRawMitigationPolicy(ProcessMitigationPolicy policy, int value)
        {
            SetRawMitigationPolicy(policy, value, true);
        }

        /// <summary>
        /// Set a mitigation policy value from an enum.
        /// </summary>
        /// <param name="policy">The policy to set</param>
        /// <param name="value">The value to set</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public NtStatus SetMitigationPolicy(ProcessMitigationPolicy policy, Enum value, bool throw_on_error)
        {
            return SetRawMitigationPolicy(policy, Convert.ToInt32(value), throw_on_error);
        }

        /// <summary>
        /// Set a mitigation policy value from an enum.
        /// </summary>
        /// <param name="policy">The policy to set</param>
        /// <param name="value">The value to set</param>
        public void SetMitigationPolicy(ProcessMitigationPolicy policy, Enum value)
        {
            SetMitigationPolicy(policy, value, true);
        }

        /// <summary>
        /// Set a mitigation policy raw value
        /// </summary>
        /// <param name="policy">The policy to set</param>
        /// <param name="value">The value to set</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        [Obsolete("Use SetMitigationPolicy or SetRawMitigationPolicy")]
        public NtStatus SetProcessMitigationPolicy(ProcessMitigationPolicy policy, int value, bool throw_on_error)
        {
            return SetRawMitigationPolicy(policy, value, throw_on_error);
        }

        /// <summary>
        /// Set a mitigation policy raw value
        /// </summary>
        /// <param name="policy">The policy to set</param>
        /// <param name="value">The value to set</param>
        [Obsolete("Use SetMitigationPolicy or SetRawMitigationPolicy")]
        public void SetProcessMitigationPolicy(ProcessMitigationPolicy policy, int value)
        {
            SetRawMitigationPolicy(policy, value);
        }

        /// <summary>
        /// Disable dynamic code policy on another process.
        /// </summary>
        public void DisableDynamicCodePolicy()
        {
            if (!NtToken.EnableDebugPrivilege())
            {
                throw new InvalidOperationException("Must have Debug privilege to disable code policy");
            }

            SetRawMitigationPolicy(ProcessMitigationPolicy.DynamicCode, 0);
        }

        /// <summary>
        /// Suspend the entire process.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public NtStatus Suspend(bool throw_on_error)
        {
            return NtSystemCalls.NtSuspendProcess(Handle).ToNtException(throw_on_error);
        }

        /// <summary>
        /// Resume the entire process.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public NtStatus Resume(bool throw_on_error)
        {
            return NtSystemCalls.NtResumeProcess(Handle).ToNtException(throw_on_error);
        }

        /// <summary>
        /// Suspend the entire process.
        /// </summary>
        public void Suspend()
        {
            Suspend(true);
        }

        /// <summary>
        /// Resume the entire process.
        /// </summary>
        public void Resume()
        {
            Resume(true);
        }

        /// <summary>
        /// Open the process' token
        /// </summary>
        /// <returns>The process token.</returns>
        public NtToken OpenToken()
        {
            return OpenToken(true).Result;
        }

        /// <summary>
        /// Open the process' token
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The process token.</returns>
        public NtResult<NtToken> OpenToken(bool throw_on_error)
        {
            return OpenToken(TokenAccessRights.MaximumAllowed, throw_on_error);
        }

        /// <summary>
        /// Open the process' token
        /// </summary>
        /// <param name="desired_access">Desired access for token.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The process token.</returns>
        public NtResult<NtToken> OpenToken(TokenAccessRights desired_access, bool throw_on_error)
        {
            return NtToken.OpenProcessToken(this, desired_access, throw_on_error);
        }

        /// <summary>
        /// Set process access token. Process must be have not been started.
        /// </summary>
        /// <param name="token">The token to set.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public NtStatus SetToken(NtToken token, bool throw_on_error)
        {
            ProcessAccessToken proc_token = new ProcessAccessToken
            {
                AccessToken = token.Handle.DangerousGetHandle()
            };
            return Set(ProcessInformationClass.ProcessAccessToken, proc_token, throw_on_error);
        }

        /// <summary>
        /// Set process access token. Process must be have not been started.
        /// </summary>
        /// <param name="token">The token to set.</param>
        public void SetToken(NtToken token)
        {
            SetToken(token, true);
        }

        /// <summary>
        /// Read memory from a process.
        /// </summary>
        /// <param name="base_address">The base address in the process.</param>
        /// <param name="length">The length to read.</param>
        /// <param name="read_all">If true ensure we read all bytes, otherwise throw on exception.</param>
        /// <returns>The array of bytes read from the location. 
        /// If a read is short then returns fewer bytes than requested.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public byte[] ReadMemory(long base_address, int length, bool read_all)
        {
            byte[] ret = NtVirtualMemory.ReadMemory(Handle, base_address, length);
            if (read_all && length != ret.Length)
            {
                throw new NtException(NtStatus.STATUS_PARTIAL_COPY);
            }
            return ret;
        }

        /// <summary>
        /// Read memory from a process.
        /// </summary>
        /// <param name="base_address">The base address in the process.</param>
        /// <param name="length">The length to read.</param>
        /// <returns>The array of bytes read from the location. 
        /// If a read is short then returns fewer bytes than requested.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public byte[] ReadMemory(long base_address, int length)
        {
            return ReadMemory(base_address, length, false);
        }

        /// <summary>
        /// Write memory to a process.
        /// </summary>
        /// <param name="base_address">The base address in the process.</param>
        /// <param name="data">The data to write.</param>
        /// <returns>The number of bytes written to the location</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public int WriteMemory(long base_address, byte[] data)
        {
            return NtVirtualMemory.WriteMemory(Handle, base_address, data);
        }

        /// <summary>
        /// Read structured memory from a process.
        /// </summary>
        /// <param name="base_address">The base address in the process.</param>
        /// <returns>The read structure.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        /// <typeparam name="T">Type of structure to read.</typeparam>
        public T ReadMemory<T>(long base_address) where T : new()
        {
            return NtVirtualMemory.ReadMemory<T>(Handle, base_address);
        }

        /// <summary>
        /// Write structured memory to a process.
        /// </summary>
        /// <param name="base_address">The base address in the process.</param>
        /// <param name="data">The data to write.</param>
        /// <exception cref="NtException">Thrown on error.</exception>
        /// <typeparam name="T">Type of structure to write.</typeparam>
        public void WriteMemory<T>(long base_address, T data) where T : new()
        {
            NtVirtualMemory.WriteMemory(Handle, base_address, data);
        }

        /// <summary>
        /// Read structured memory array from a process.
        /// </summary>
        /// <param name="base_address">The base address in the process.</param>
        /// <param name="count">The number of elements in the array to read.</param>
        /// <returns>The read structure.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        /// <typeparam name="T">Type of structure to read.</typeparam>
        public T[] ReadMemoryArray<T>(long base_address, int count) where T : new()
        {
            return NtVirtualMemory.ReadMemoryArray<T>(Handle, base_address, count);
        }

        /// <summary>
        /// Write structured memory array to a process.
        /// </summary>
        /// <param name="base_address">The base address in the process.</param>
        /// <param name="data">The data array to write.</param>
        /// <exception cref="NtException">Thrown on error.</exception>
        /// <typeparam name="T">Type of structure to write.</typeparam>
        public void WriteMemoryArray<T>(long base_address, T[] data) where T : new()
        {
            NtVirtualMemory.WriteMemoryArray(Handle, base_address, data);
        }

        /// <summary>
        /// Query memory information for a process.
        /// </summary>
        /// <param name="base_address">The base address.</param>
        /// <returns>The queries memory information.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public MemoryInformation QueryMemoryInformation(long base_address)
        {
            return NtVirtualMemory.QueryMemoryInformation(Handle, base_address);
        }

        /// <summary>
        /// Query all memory information regions in process memory.
        /// </summary>
        /// <returns>The list of memory regions.</returns>
        /// <param name="type">Specify memory types to filter on.</param>
        /// <param name="state">Set of flags which indicate the memory states to return.</param>
        /// <exception cref="NtException">Thrown on error.</exception>
        public IEnumerable<MemoryInformation> QueryAllMemoryInformation(MemoryType type, MemoryState state)
        {
            var mem_infos = NtVirtualMemory.QueryMemoryInformation(Handle);

            if (state != MemoryState.All)
            {
                mem_infos = mem_infos.Where(m => m.State.HasFlagSet(state));
            }

            if (type != MemoryType.All)
            {
                mem_infos = mem_infos.Where(m => (m.Type & type) != MemoryType.None);
            }

            return mem_infos;
        }

        /// <summary>
        /// Query all memory information regions in process memory.
        /// </summary>
        /// <returns>The list of memory regions.</returns>
        /// <param name="include_free_regions">True to include free regions of memory.</param>
        /// <param name="type">Specify memory types to filter on.</param>
        /// <exception cref="NtException">Thrown on error.</exception>
        public IEnumerable<MemoryInformation> QueryAllMemoryInformation(bool include_free_regions, MemoryType type)
        {
            return QueryAllMemoryInformation(type, MemoryState.Commit | MemoryState.Reserve | (include_free_regions ? MemoryState.Free : 0));
        }

        /// <summary>
        /// Query all memory information regions in process memory.
        /// </summary>
        /// <returns>The list of memory regions.</returns>
        /// <param name="include_free_regions">True to include free regions of memory.</param>
        /// <exception cref="NtException">Thrown on error.</exception>
        public IEnumerable<MemoryInformation> QueryAllMemoryInformation(bool include_free_regions)
        {
            return QueryAllMemoryInformation(include_free_regions, MemoryType.All);
        }

        /// <summary>
        /// Query all memory information regions in process memory excluding free regions.
        /// </summary>
        /// <returns>The list of memory regions.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public IEnumerable<MemoryInformation> QueryAllMemoryInformation()
        {
            return QueryAllMemoryInformation(false);
        }

        /// <summary>
        /// Query a list of mapped images in a process.
        /// </summary>
        /// <returns>The list of mapped images</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public IEnumerable<MappedFile> QueryMappedImages()
        {
            return QueryAllMappedFiles().Where(m => m.IsImage);
        }

        /// <summary>
        /// Query a list of mapped files in a process.
        /// </summary>
        /// <returns>The list of mapped images</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public IEnumerable<MappedFile> QueryMappedFiles()
        {
            return QueryAllMappedFiles().Where(m => !m.IsImage);
        }

        /// <summary>
        /// Query a list of all mapped files and images in a process.
        /// </summary>
        /// <returns>The list of mapped images</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public IEnumerable<MappedFile> QueryAllMappedFiles()
        {
            return NtVirtualMemory.QueryMappedFiles(Handle);
        }

        /// <summary>
        /// Allocate virtual memory in a process.
        /// </summary>
        /// <param name="base_address">Optional base address, if 0 will automatically select a base.</param>
        /// <param name="region_size">The region size to allocate.</param>
        /// <param name="allocation_type">The type of allocation.</param>
        /// <param name="protect">The allocation protection.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The address of the allocated region.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public NtResult<long> AllocateMemory(long base_address,
            long region_size,
            MemoryAllocationType allocation_type, MemoryAllocationProtect protect,
            bool throw_on_error)
        {
            return NtVirtualMemory.AllocateMemory(Handle, base_address,
                region_size, allocation_type, protect, throw_on_error);
        }

        /// <summary>
        /// Allocate virtual memory in a process.
        /// </summary>
        /// <param name="base_address">Optional base address, if 0 will automatically select a base.</param>
        /// <param name="region_size">The region size to allocate.</param>
        /// <param name="allocation_type">The type of allocation.</param>
        /// <param name="protect">The allocation protection.</param>
        /// <returns>The address of the allocated region.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public long AllocateMemory(long base_address,
            long region_size,
            MemoryAllocationType allocation_type, MemoryAllocationProtect protect)
        {
            return AllocateMemory(base_address, region_size, allocation_type, protect, true).Result;
        }

        /// <summary>
        /// Allocate read/write virtual memory in a process.
        /// </summary>
        /// <param name="region_size">The region size to allocate.</param>
        /// <returns>The address of the allocated region.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public long AllocateMemory(long region_size)
        {
            return AllocateMemory(0, region_size,
                MemoryAllocationType.Reserve | MemoryAllocationType.Commit,
                MemoryAllocationProtect.ReadWrite);
        }

        /// <summary>
        /// Free virtual emmory in a process.
        /// </summary>
        /// <param name="base_address">Base address of region to free</param>
        /// <param name="region_size">The size of the region.</param>
        /// <param name="free_type">The type to free.</param>
        /// <exception cref="NtException">Thrown on error.</exception>
        public void FreeMemory(long base_address, long region_size, MemoryFreeType free_type)
        {
            NtVirtualMemory.FreeMemory(Handle, base_address, region_size, free_type);
        }

        /// <summary>
        /// Free virtual emmory in a process.
        /// </summary>
        /// <param name="base_address">Base address of region to free</param>
        /// <param name="region_size">The size of the region.</param>
        /// <param name="free_type">The type to free.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <exception cref="NtException">Thrown on error.</exception>
        public NtStatus FreeMemory(long base_address, long region_size, MemoryFreeType free_type, bool throw_on_error)
        {
            return NtVirtualMemory.FreeMemory(Handle, base_address, region_size, free_type, throw_on_error);
        }

        /// <summary>
        /// Change protection on a region of memory.
        /// </summary>
        /// <param name="base_address">The base address</param>
        /// <param name="region_size">The size of the memory region.</param>
        /// <param name="new_protect">The new protection type.</param>
        /// <returns>The old protection for the region.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public MemoryAllocationProtect ProtectMemory(long base_address,
            long region_size, MemoryAllocationProtect new_protect)
        {
            return NtVirtualMemory.ProtectMemory(Handle, base_address,
                region_size, new_protect);
        }

        /// <summary>
        /// Change protection on a region of memory.
        /// </summary>
        /// <param name="base_address">The base address</param>
        /// <param name="region_size">The size of the memory region.</param>
        /// <param name="new_protect">The new protection type.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The old protection for the region.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public NtResult<MemoryAllocationProtect> ProtectMemory(long base_address,
            long region_size, MemoryAllocationProtect new_protect, bool throw_on_error)
        {
            return NtVirtualMemory.ProtectMemory(Handle, base_address,
                region_size, new_protect, throw_on_error);
        }

        /// <summary>
        /// Flush instruction cache.
        /// </summary>
        /// <param name="address">The address to flush.</param>
        /// <param name="count">The number of bytes to flush/</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public NtStatus FlushInstructionCache(long address, int count, bool throw_on_error)
        {
            return NtVirtualMemory.FlushInstructionCache(Handle, address, count, throw_on_error);
        }

        /// <summary>
        /// Flush instruction cache.
        /// </summary>
        /// <param name="address">The address to flush.</param>
        /// <param name="count">The number of bytes to flush/</param>
        public void FlushInstructionCache(long address, int count)
        {
            FlushInstructionCache(address, count, true);
        }

        /// <summary>
        /// Query working set information for an address in a process.
        /// </summary>
        /// <param name="base_address">The base address to query.</param>
        /// <param name="throw_on_error">True to throw on error</param>
        /// <returns>The working set information.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public NtResult<MemoryWorkingSetExInformation> QueryWorkingSetEx(long base_address, bool throw_on_error)
        {
            return NtVirtualMemory.QueryWorkingSetEx(Handle, base_address, throw_on_error);
        }

        /// <summary>
        /// Query working set information for an address in a process.
        /// </summary>
        /// <param name="base_address">The base address to query.</param>
        /// <returns>The working set information.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public MemoryWorkingSetExInformation QueryWorkingSetEx(long base_address)
        {
            return QueryWorkingSetEx(base_address, true).Result;
        }

        /// <summary>
        /// Set the process device map.
        /// </summary>
        /// <param name="device_map">The device map directory to set.</param>
        /// <remarks>Note that due to a bug in the Wow64 layer this won't work in a 32 bit process on a 64 bit system.</remarks>
        public void SetDeviceMap(NtDirectory device_map)
        {
            SetDeviceMap(device_map, true);
        }

        /// <summary>
        /// Set the process device map.
        /// </summary>
        /// <param name="device_map">The device map directory to set.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <remarks>Note that due to a bug in the Wow64 layer this won't work in a 32 bit process on a 64 bit system.</remarks>
        public NtStatus SetDeviceMap(NtDirectory device_map, bool throw_on_error)
        {
            var device_map_set = new ProcessDeviceMapInformationSet
            {
                DirectoryHandle = device_map.Handle.DangerousGetHandle()
            };

            return Set(ProcessInformationClass.ProcessDeviceMap, device_map_set, throw_on_error);
        }

        /// <summary>
        /// Set the process device map.
        /// </summary>
        /// <param name="device_map">The device map directory to set.</param>
        /// <remarks>Note that due to a bug in the Wow64 layer this won't work in a 32 bit process on a 64 bit system.</remarks>
        [Obsolete("Use SetDeviceMap")]
        public void SetProcessDeviceMap(NtDirectory device_map)
        {
            SetDeviceMap(device_map);
        }

        /// <summary>
        /// Set the process device map.
        /// </summary>
        /// <param name="device_map">The device map directory to set.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <remarks>Note that due to a bug in the Wow64 layer this won't work in a 32 bit process on a 64 bit system.</remarks>
        [Obsolete("Use SetDeviceMap")]
        public NtStatus SetProcessDeviceMap(NtDirectory device_map, bool throw_on_error)
        {
            return SetDeviceMap(device_map, throw_on_error);
        }

        /// <summary>
        /// Open a process' debug object.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The process' debug object.</returns>
        public NtResult<NtDebug> OpenDebugObject(bool throw_on_error)
        {
            return Query(ProcessInformationClass.ProcessDebugObjectHandle, IntPtr.Zero, throw_on_error).Map(r => NtDebug.FromHandle(r, true));
        }

        /// <summary>
        /// Open a process' debug object.
        /// </summary>
        /// <returns>The process' debug object.</returns>
        public NtDebug OpenDebugObject()
        {
            return OpenDebugObject(true).Result;
        }

        /// <summary>
        /// Queries whether process is backed by a specific file.
        /// </summary>
        /// <param name="file">File object opened with Synchronize and Execute access to test against.</param>
        /// <returns>True if the process is created from the image file.</returns>
        public bool IsImageFile(NtFile file)
        {
            return Query(ProcessInformationClass.ProcessImageFileMapping, file.Handle.DangerousGetHandle(), false).IsSuccess;
        }

        /// <summary>
        /// Open parent process by ID.
        /// </summary>
        /// <param name="desired_access">The desired process access rights.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The opened process.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public NtResult<NtProcess> OpenParent(ProcessAccessRights desired_access, bool throw_on_error)
        {
            return Open(ParentProcessId, desired_access, throw_on_error);
        }

        /// <summary>
        /// Open parent process by ID.
        /// </summary>
        /// <param name="desired_access">The desired process access rights.</param>
        /// <returns>The opened process.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public NtProcess OpenParent(ProcessAccessRights desired_access)
        {
            return OpenParent(desired_access, true).Result;
        }

        /// <summary>
        /// Open parent process by ID.
        /// </summary>
        /// <returns>The opened process.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public NtProcess OpenParent()
        {
            return OpenParent(ProcessAccessRights.MaximumAllowed);
        }

        /// <summary>
        /// Open owner process by ID.
        /// </summary>
        /// <param name="desired_access">The desired process access rights.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The opened process.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public NtResult<NtProcess> OpenOwner(ProcessAccessRights desired_access, bool throw_on_error)
        {
            return Open(OwnerProcessId, desired_access, throw_on_error);
        }

        /// <summary>
        /// Open owner process by ID.
        /// </summary>
        /// <param name="desired_access">The desired process access rights.</param>
        /// <returns>The opened process.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public NtProcess OpenOwner(ProcessAccessRights desired_access)
        {
            return OpenOwner(desired_access, true).Result; ;
        }

        /// <summary>
        /// Open owner process by ID.
        /// </summary>
        /// <returns>The opened process.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public NtProcess OpenOwner()
        {
            return OpenOwner(ProcessAccessRights.MaximumAllowed);
        }

        /// <summary>
        /// Get if process is in a job.
        /// </summary>
        /// <param name="job">A specific job to check</param>
        /// <returns>True if in specific job.</returns>
        public bool IsInJob(NtJob job)
        {
            return NtSystemCalls.NtIsProcessInJob(Handle,
                job.GetHandle()) == NtStatus.STATUS_PROCESS_IN_JOB;
        }

        /// <summary>
        /// Get if process is in a job.
        /// </summary>
        /// <returns>True if in a job.</returns>
        public bool IsInJob()
        {
            return IsInJob(null);
        }

        /// <summary>
        /// Get process handle table.
        /// </summary>
        /// <returns>The list of process handles.</returns>
        public IEnumerable<int> GetHandleTable()
        {
            // Try handle count + 1000 (just to give a bit of space)
            // If you want this to be reliable you probably need to suspend the process.
            using (var buf = new SafeHGlobalBuffer((HandleCount + 1000) * 4))
            {
                NtSystemCalls.NtQueryInformationProcess(Handle, ProcessInformationClass.ProcessHandleTable,
                    buf, buf.Length, out int return_length).ToNtException();
                int[] ret = new int[return_length / 4];
                buf.ReadArray(0, ret, 0, ret.Length);
                return ret;
            }
        }

        /// <summary>
        /// Get handles for process.
        /// </summary>
        /// <param name="allow_query">Specify to all name/details to be queried from the handle.</param>
        /// <param name="force_file_query">Force file query for name/details for non-filesystem handles.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The list of handles.</returns>
        /// <remarks>This queries the handles from the process which does not contain the Object's addres in kernel memory.</remarks>
        public NtResult<IEnumerable<NtHandle>> GetHandles(bool allow_query, bool force_file_query, bool throw_on_error)
        {
            string path = FullPath;
            using (var buffer = QueryBuffer<ProcessHandleSnapshotInformation>(ProcessInformationClass.ProcessHandleInformation, default, throw_on_error))
            {
                if (!buffer.IsSuccess)
                    return buffer.Cast<IEnumerable<NtHandle>>();
                var info = buffer.Result;
                ProcessHandleTableEntryInfo[] handles = new ProcessHandleTableEntryInfo[info.Result.NumberOfHandles.ToInt32()];
                info.Data.ReadArray(0, handles, 0, handles.Length);
                return handles.Select(h => new NtHandle(ProcessId, h, allow_query, force_file_query, path)).ToArray().CreateResult<IEnumerable<NtHandle>>();
            }
        }

        /// <summary>
        /// Get handles for process.
        /// </summary>
        /// <param name="allow_query">Specify to all name/details to be queried from the handle.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The list of handles.</returns>
        /// <remarks>This queries the handles from the process which does not contain the Object's addres in kernel memory.</remarks>
        public NtResult<IEnumerable<NtHandle>> GetHandles(bool allow_query, bool throw_on_error)
        {
            return GetHandles(allow_query, false, throw_on_error);
        }

        /// <summary>
        /// Get handles for process.
        /// </summary>
        /// <param name="allow_query">Specify to all name/details to be queried from the handle.</param>
        /// <returns>The list of handles.</returns>
        /// <remarks>This queries the handles from the process which does not contain the Object's addres in kernel memory.</remarks>
        public IEnumerable<NtHandle> GetHandles(bool allow_query)
        {
            return GetHandles(allow_query, false, true).Result;
        }

        /// <summary>
        /// Get handles for process.
        /// </summary>
        /// <returns>The list of handles.</returns>
        /// <remarks>This queries the handles from the process which does not contain the Object's addres in kernel memory.</remarks>
        public IEnumerable<NtHandle> GetHandles()
        {
            return GetHandles(true);
        }

        /// <summary>
        /// Get the process handle table and try and get them as objects.
        /// </summary>
        /// <param name="named_only">True to only return named objects</param>
        /// <param name="type_names">A list of typenames to filter on (if empty then return all)</param>
        /// <returns>The list of handles as objects.</returns>
        /// <remarks>This function will drop handles it can't duplicate.</remarks>
        public IEnumerable<NtObject> GetHandleTableAsObjects(bool named_only, IEnumerable<string> type_names)
        {
            if (!IsAccessGranted(ProcessAccessRights.DupHandle))
            {
                return new NtObject[0];
            }

            List<NtObject> objs = new List<NtObject>();
            HashSet<string> types = new HashSet<string>(type_names, StringComparer.OrdinalIgnoreCase);
            foreach (int handle in GetHandleTable())
            {
                try
                {
                    using (NtGeneric generic = NtGeneric.DuplicateFrom(this, new IntPtr(handle)))
                    {
                        if (named_only && generic.FullPath == string.Empty)
                        {
                            continue;
                        }

                        if (types.Count > 0 && !types.Contains(generic.NtTypeName))
                        {
                            continue;
                        }

                        objs.Add(generic.ToTypedObject());
                    }
                }
                catch (NtException)
                {
                }
            }
            return objs;
        }

        /// <summary>
        /// Get the process handle table and try and get them as objects.
        /// </summary>
        /// <returns>The list of handles as objects.</returns>
        /// <remarks>This function will drop handles it can't duplicate.</remarks>
        public IEnumerable<NtObject> GetHandleTableAsObjects()
        {
            return GetHandleTableAsObjects(false, new string[0]);
        }

        /// <summary>
        /// Open image section for process.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The opened image section.</returns>
        /// <remarks>Should only work on the pseudo process handle.</remarks>
        public NtResult<NtSection> OpenImageSection(bool throw_on_error)
        {
            return Query(ProcessInformationClass.ProcessImageSection,
                IntPtr.Zero, throw_on_error).Map(r => NtSection.FromHandle(r, true));
        }

        /// <summary>
        /// Open image section for process.
        /// </summary>
        /// <returns>The opened image section.</returns>
        /// <remarks>Should only work on the pseudo process handle.</remarks>
        public NtSection OpenImageSection()
        {
            return OpenImageSection(true).Result;
        }

        /// <summary>
        /// Unmap a section.
        /// </summary>
        /// <param name="base_address">The base address to unmap.</param>
        /// <param name="flags">Flags for unmapping memory.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public NtStatus Unmap(IntPtr base_address, MemUnmapFlags flags, bool throw_on_error)
        {
            return NtSection.Unmap(this, base_address, flags, throw_on_error);
        }

        /// <summary>
        /// Unmap a section.
        /// </summary>
        /// <param name="base_address">The base address to unmap.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public NtStatus Unmap(IntPtr base_address, bool throw_on_error)
        {
            return Unmap(base_address, MemUnmapFlags.None, throw_on_error);
        }

        /// <summary>
        /// Unmap a section.
        /// </summary>
        /// <param name="base_address">The base address to unmap.</param>
        /// <param name="flags">Flags for unmapping memory.</param>
        public void Unmap(IntPtr base_address, MemUnmapFlags flags)
        {
            Unmap(base_address, flags, true);
        }

        /// <summary>
        /// Unmap a section.
        /// </summary>
        /// <param name="base_address">The base address to unmap.</param>
        public void Unmap(IntPtr base_address)
        {
            Unmap(base_address, true);
        }

        /// <summary>
        /// Get the user SID for the process.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The user SID.</returns>
        public NtResult<Sid> GetUser(bool throw_on_error)
        {
            using (var token = OpenToken(TokenAccessRights.Query, throw_on_error))
            {
                return token.Map(t => t.User.Sid);
            }
        }

        /// <summary>
        /// Get the user SID for the process.
        /// </summary>
        /// <returns>The user SID.</returns>
        public Sid GetUser()
        {
            return GetUser(true).Result;
        }

        /// <summary>
        /// Get the integrity level for the process.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The integerity level.</returns>
        public NtResult<TokenIntegrityLevel> GetIntegrityLevel(bool throw_on_error)
        {
            using (var token = OpenToken(TokenAccessRights.Query, throw_on_error))
            {
                return token.Map(t => t.IntegrityLevel);
            }
        }

        /// <summary>
        /// Set process fault flags.
        /// </summary>
        /// <param name="flags">The flags to set.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code for the operation.</returns>
        public NtStatus SetFaultFlags(ProcessFaultFlags flags, bool throw_on_error)
        {
            return Set(ProcessInformationClass.ProcessFaultInformation, new ProcessFaultInformation() { FaultFlags = flags }, throw_on_error);
        }

        /// <summary>
        /// Set process fault flags.
        /// </summary>
        /// <param name="flags">The flags to set.</param>
        /// <returns>The NT status code for the operation.</returns>
        public void SetFaultFlags(ProcessFaultFlags flags)
        {
            SetFaultFlags(flags, true);
        }

        /// <summary>
        /// Set the process exception port.
        /// </summary>
        /// <param name="exception_port">The exception port to set.</param>
        /// <param name="state_flags">Additional state flags.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public NtStatus SetExceptionPort(NtAlpc exception_port, int state_flags, bool throw_on_error)
        {
            ProcessExceptionPort port = new ProcessExceptionPort()
            {
                ExceptionPortHandle = exception_port.Handle.DangerousGetHandle(),
                StateFlags = state_flags
            };
            return Set(ProcessInformationClass.ProcessExceptionPort, port, throw_on_error);
        }

        /// <summary>
        /// Set the process exception port.
        /// </summary>
        /// <param name="exception_port">The exception port to set.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public NtStatus SetExceptionPort(NtAlpc exception_port, bool throw_on_error)
        {
            return Set(ProcessInformationClass.ProcessExceptionPort, exception_port.Handle.DangerousGetHandle(), throw_on_error);
        }

        /// <summary>
        /// Set the process exception port.
        /// </summary>
        /// <param name="exception_port">The exception port to set.</param>
        /// <returns>The NT status code.</returns>
        public void SetExceptionPort(NtAlpc exception_port)
        {
            SetExceptionPort(exception_port, true);
        }

        /// <summary>
        /// Get the user process parameters.
        /// </summary>
        /// <returns>The user process parameters.</returns>
        public NtUserProcessParameters GetUserProcessParameters()
        {
            if (!Environment.Is64BitProcess && Is64Bit)
            {
                throw new ArgumentException("Do not support 32 to 64 bit reading.");
            }

            var peb = GetPeb();
            var params_ptr = peb.GetProcessParameters().ToInt64();
            if (params_ptr == 0)
                throw new NtException(NtStatus.STATUS_INSUFFICIENT_RESOURCES);

            var header = ReadMemory<RtlUserProcessParametersHeader>(params_ptr);
            byte[] bytes = ReadMemory(params_ptr, header.Length);
            RtlUserProcessParameters user_params;
            if (Environment.Is64BitProcess != Is64Bit)
            {
                using (var buffer = new SafeStructureInOutBuffer<RtlUserProcessParameters32>())
                {
                    buffer.FillBuffer(0);
                    buffer.WriteArray(0, bytes, 0, Math.Min(bytes.Length, buffer.Length));
                    user_params = buffer.Result.Convert();
                }
            }
            else
            {
                using (var buffer = new SafeStructureInOutBuffer<RtlUserProcessParameters>())
                {
                    buffer.FillBuffer(0);
                    buffer.WriteArray(0, bytes, 0, Math.Min(bytes.Length, buffer.Length));
                    user_params = buffer.Result;
                }
            }
            return user_params.ToObject(this);
        }

        /// <summary>
        /// Fork the process.
        /// </summary>
        /// <param name="flags">Extra flags for fork.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The new forked process result.</returns>
        /// <remarks>This uses NtCreateProcessEx.</remarks>
        public NtResult<NtProcess> Fork(ProcessCreateFlags flags, bool throw_on_error)
        {
            return Create(null, ProcessAccessRights.MaximumAllowed,
                this, flags | ProcessCreateFlags.InheritFromParent, null, null, null, throw_on_error);
        }

        /// <summary>
        /// Fork the process.
        /// </summary>
        /// <param name="flags">Extra flags for fork.</param>
        /// <returns>The new forked process result.</returns>
        /// <remarks>This uses NtCreateProcessEx.</remarks>
        public NtProcess Fork(ProcessCreateFlags flags)
        {
            return Fork(flags, true).Result;
        }

        /// <summary>
        /// Fork the process.
        /// </summary>
        /// <returns>The new forked process result.</returns>
        /// <remarks>This uses NtCreateProcessEx.</remarks>
        public NtProcess Fork()
        {
            return Fork(ProcessCreateFlags.None);
        }

        /// <summary>
        /// Get the accessible job objects this process is in.
        /// </summary>
        /// <remarks>This tries to find accessible Job handles. There's no guarantee that all Job objects will be found for the process.</remarks>
        /// <returns>The list of job objects.</returns>
        public IEnumerable<NtJob> GetAccessibleJobObjects()
        {
            HashSet<ulong> jobs = new HashSet<ulong>();
            if (!IsInJob())
                yield break;
            foreach (var h in NtSystemInfo.GetHandles())
            {
                if (h.ObjectType == "Job" && jobs.Add(h.Object))
                {
                    using (var result = h.GetObject(false).Cast<NtJob>())
                    {
                        if (!result.IsSuccess || !IsInJob(result.Result))
                        {
                            continue;
                        }
                        yield return result.Result.Duplicate();
                    }
                }
            }
        }

        /// <summary>
        /// Set thread intelligence logging flags.
        /// </summary>
        /// <param name="flags">The flags to set.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public NtStatus SetProcessLogging(ProcessLoggingFlags flags, bool throw_on_error)
        {
            ProcessInformationClass info_class;
            if ((flags & (ProcessLoggingFlags.ProcessSuspendResume | ProcessLoggingFlags.ThreadSuspendResume)) != 0)
            {
                info_class = ProcessInformationClass.ProcessEnableLogging;
            }
            else
            {
                info_class = ProcessInformationClass.ProcessEnableReadWriteVmLogging;
            }

            return Set(info_class, (int)flags, throw_on_error);
        }

        /// <summary>
        /// Set thread intelligence logging flags.
        /// </summary>
        /// <param name="flags">The flags to set.</param>
        public void SetProcessLogging(ProcessLoggingFlags flags)
        {
            SetProcessLogging(flags, true);
        }

        /// <summary>
        /// Get the process security domain.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The security domain.</returns>
        public NtResult<long> GetSecurityDomain(bool throw_on_error)
        {
            return Query(ProcessInformationClass.ProcessSecurityDomainInformation,
                new ProcessSecurityDomainInformation(), throw_on_error).Map(r => r.SecurityDomain);
        }

        /// <summary>
        /// Get the process security domain.
        /// </summary>
        /// <returns>The security domain.</returns>
        public long GetSecurityDomain()
        {
            return GetSecurityDomain(true).Result;
        }

        /// <summary>
        /// Combine two process' security domains.
        /// </summary>
        /// <param name="process">The process to combine with. Needs QueryLimitedInformation.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        /// <remarks>The current process need SetLimitedInformation access.</remarks>
        public NtStatus CombineSecurityDomain(NtProcess process, bool throw_on_error)
        {
            var info = new ProcessCombineSecurityDomainInformation()
            {
                ProcessHandle = process.Handle.DangerousGetHandle()
            };
            return Set(ProcessInformationClass.ProcessCombineSecurityDomainsInformation, info, throw_on_error);
        }

        /// <summary>
        /// Combine two process' security domains.
        /// </summary>
        /// <param name="process">The process to combine with. Needs QueryLimitedInformation.</param>
        /// <remarks>The current process need SetLimitedInformation access.</remarks>
        public void CombineSecurityDomain(NtProcess process)
        {
            CombineSecurityDomain(process, true);
        }

        /// <summary>
        /// Get the session ID for the process.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The session ID.</returns>
        public NtResult<int> GetSessionId(bool throw_on_error)
        {
            return Query<ProcessSessionInformation>(ProcessInformationClass.ProcessSessionInformation, 
                default, throw_on_error).Map(s => s.SessionId);
        }

        /// <summary>
        /// Test whether the current process can access another protected process.
        /// </summary>
        /// <param name="target">The target process.</param>
        /// <returns>True if the process can be accessed.</returns>
        public bool TestProtectedAccess(NtProcess target)
        {
            return TestProtectedAccess(this, target);
        }

        /// <summary>
        /// Get the environment from the process.
        /// </summary>
        /// <returns>List of environment variables.</returns>
        public IReadOnlyList<NtProcessEnvironmentVariable> GetEnvironment()
        {
            var proc_params = GetUserProcessParameters();
            int env_size;
            if (NtObjectUtils.SupportedVersion < SupportedVersion.Windows10_RS5)
            {
                var mem_info = QueryMemoryInformation(proc_params.Environment.ToInt64());
                long curr_size = mem_info.RegionSize - (proc_params.Environment.ToInt64() - mem_info.BaseAddress);
                env_size = (int)curr_size;
            }
            else
            {
                env_size = proc_params.EnvironmentSize.ToInt32();
            }

            return NtProcessEnvironmentVariable.ParseEnvironmentBlock(
                ReadMemory(proc_params.Environment.ToInt64(), env_size, true)).ToList().AsReadOnly();
        }

        /// <summary>
        /// Get an environment variable by name.
        /// </summary>
        /// <param name="name">The name of the variable.</param>
        /// <returns>The value of the environment variable. Returns null if it doesn't exist.</returns>
        /// <remarks>Only returns the first variable with a case insensitive name.</remarks>
        public string GetEnvironmentVariable(string name)
        {
            return GetEnvironment().Where(v => v.Name.Equals(name, StringComparison.OrdinalIgnoreCase)).FirstOrDefault().Value;
        }

        /// <summary>
        /// Revoke file handles for an AppContainer process.
        /// </summary>
        /// <param name="device_path">The device path for the files to revoke.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public NtStatus RevokeFileHandles(string device_path, bool throw_on_error)
        {
            return Set(ProcessInformationClass.ProcessRevokeFileHandles, 
                new ProcessRevokeFileHandlesInformation() { TargetDevicePath = new UnicodeString(device_path) },
                throw_on_error);
        }

        /// <summary>
        /// Revoke file handles for an AppContainer process.
        /// </summary>
        /// <param name="device_path">The device path for the files to revoke.</param>
        public void RevokeFileHandles(string device_path)
        {
            RevokeFileHandles(device_path, true);
        }

        /// <summary>
        /// Get the process command line.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The process command line.</returns>
        public NtResult<string> GetCommandLine(bool throw_on_error)
        {
            using (var result = QueryBuffer(ProcessInformationClass.ProcessCommandLineInformation, new UnicodeStringOut(), false))
            {
                return result.Map(b => b.Result.ToString());
            }
        }

        /// <summary>
        /// Get the IO counters for the process.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The IO counters.</returns>
        public NtResult<IoCounters> GetIoCounters(bool throw_on_error)
        {
            return Query<IoCounters>(ProcessInformationClass.ProcessIoCounters, default, throw_on_error);
        }

        /// <summary>
        /// Create a VBS enclave.
        /// </summary>
        /// <param name="size">Size of the enclave.</param>
        /// <param name="flags">Flags for the enclave.</param>
        /// <param name="owner_id">Owner ID. Must be 32 bytes.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The created enclave.</returns>
        public NtResult<NtEnclaveVBS> CreateEnclaveVBS(
            long size,
            LdrEnclaveVBSFlags flags,
            byte[] owner_id,
            bool throw_on_error)
        {
            return NtEnclaveVBS.Create(Handle, size, flags, owner_id, throw_on_error);
        }

        /// <summary>
        /// Create a VBS enclave.
        /// </summary>
        /// <param name="size">Size of the enclave.</param>
        /// <param name="flags">Flags for the enclave.</param>
        /// <param name="owner_id">Owner ID. Must be 32 bytes.</param>
        /// <returns>The created enclave.</returns>
        public NtEnclaveVBS CreateEnclaveVBS(
            long size,
            LdrEnclaveVBSFlags flags,
            byte[] owner_id)
        {
            return CreateEnclaveVBS(size, flags, owner_id, true).Result;
        }

        /// <summary>
        /// Get priority boost disable value.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>True if priority base </returns>
        public NtResult<bool> GetPriorityBoostDisabled(bool throw_on_error)
        {
            return Query(ProcessInformationClass.ProcessPriorityBoost, 0, throw_on_error).Map(i => i != 0);
        }

        /// <summary>
        /// Set priority boost disable value.
        /// </summary>
        /// <param name="disable">True to disable priority boost.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public NtStatus SetPriorityBoostDisabled(bool disable, bool throw_on_error)
        {
            return Set(ProcessInformationClass.ProcessPriorityBoost, disable ? 1 : 0, throw_on_error);
        }

        /// <summary>
        /// Method to query information for this object type.
        /// </summary>
        /// <param name="info_class">The information class.</param>
        /// <param name="buffer">The buffer to return data in.</param>
        /// <param name="return_length">Return length from the query.</param>
        /// <returns>The NT status code for the query.</returns>
        public override NtStatus QueryInformation(ProcessInformationClass info_class, SafeBuffer buffer, out int return_length)
        {
            return NtSystemCalls.NtQueryInformationProcess(Handle, info_class, buffer, buffer.GetLength(), out return_length);
        }

        /// <summary>
        /// Method to set information for this object type.
        /// </summary>
        /// <param name="info_class">The information class.</param>
        /// <param name="buffer">The buffer to set data from.</param>
        /// <returns>The NT status code for the set.</returns>
        public override NtStatus SetInformation(ProcessInformationClass info_class, SafeBuffer buffer)
        {
            return NtSystemCalls.NtSetInformationProcess(Handle, info_class, buffer, buffer.GetLength());
        }

        /// <summary>
        /// Query the information class as an object.
        /// </summary>
        /// <param name="info_class">The information class.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The information class as an object.</returns>
        public override NtResult<object> QueryObject(ProcessInformationClass info_class, bool throw_on_error)
        {
            switch (info_class)
            {
                case ProcessInformationClass.ProcessBasicInformation:
                    return Query<ProcessBasicInformation>(info_class, default, throw_on_error);
                case ProcessInformationClass.ProcessIoCounters:
                    return Query<IoCounters>(info_class, default, throw_on_error);
                case ProcessInformationClass.ProcessTimes:
                    return Query<KernelUserTimes>(info_class, default, throw_on_error);
                case ProcessInformationClass.ProcessQuotaLimits:
                    return Query<QuotaLimitsEx>(info_class, default, throw_on_error);
                case ProcessInformationClass.ProcessVmCounters:
                    return Query<VmCountersEx>(info_class, default, throw_on_error);
                case ProcessInformationClass.ProcessCycleTime:
                    return Query<ProcessCycleTimeInformation>(info_class, default, throw_on_error);
                case ProcessInformationClass.ProcessProtectionInformation:
                    return Query<PsProtection>(info_class, default, throw_on_error);
            }
            return base.QueryObject(info_class, throw_on_error);
        }

        #endregion

        #region Public Properties

        /// <summary>
        /// Get the process' session ID
        /// </summary>
        public int SessionId => GetSessionId(true).Result;

        /// <summary>
        /// Get the process' ID
        /// </summary>
        public int ProcessId
        {
            get
            {
                if (!_pid.HasValue)
                {
                    _pid = GetBasicInfo().UniqueProcessId.ToInt32();
                }
                return _pid.Value;
            }
        }

        /// <summary>
        /// Get the process' parent process ID
        /// </summary>
        public int ParentProcessId => GetBasicInfo().InheritedFromUniqueProcessId.ToInt32();

        /// <summary>
        /// Get the memory address of the PEB
        /// </summary>
        public IntPtr PebAddress => GetBasicInfo().PebBaseAddress;

        /// <summary>
        /// Get the memory address of the PEB for a 32 bit process.
        /// </summary>
        /// <remarks>If the process is 64 bit, or the OS is 32 bit this returns the same value as PebAddress.</remarks>
        public IntPtr PebAddress32
        {
            get
            {
                if (!Wow64)
                {
                    return PebAddress;
                }
                return Query<IntPtr>(ProcessInformationClass.ProcessWow64Information);
            }
        }

        /// <summary>
        /// Get the base address of the process from the PEB.
        /// </summary>
        public IntPtr ImageBaseAddress => GetPeb().GetImageBaseAddress();

        /// <summary>
        /// Read flags from PEB.
        /// </summary>
        public PebFlags PebFlags => GetPeb().GetPebFlags();

        /// <summary>
        /// Get the process' exit status.
        /// </summary>
        public int ExitStatus => GetExtendedBasicInfo(false).BasicInfo.ExitStatus;

        /// <summary>
        /// Get the process' exit status as an NtStatus code.
        /// </summary>
        public NtStatus ExitNtStatus => (NtStatus)ExitStatus;

        /// <summary>
        /// Get the process' command line
        /// </summary>
        public string CommandLine
        {
            get
            {
                using (var result = GetCommandLine(false))
                {
                    if (result.IsSuccess)
                        return result.Result;

                    // This will fail if process is being torn down, just return an empty string.
                    if (result.Status == NtStatus.STATUS_PROCESS_IS_TERMINATING
                        || result.Status == NtStatus.STATUS_PARTIAL_COPY
                        || result.Status == NtStatus.STATUS_NOT_FOUND)
                    {
                        return string.Empty;
                    }

                    throw new NtException(result.Status);
                }
            }
        }

        /// <summary>
        /// Get the command line as parsed arguments.
        /// </summary>
        public string[] CommandLineArguments => Win32Utils.ParseCommandLine(GetCommandLine(false).GetResultOrDefault(string.Empty));

        /// <summary>
        /// Get process DEP status
        /// </summary>
        public ProcessDepStatus DepStatus
        {
            get
            {
                using (SafeStructureInOutBuffer<uint> buffer = new SafeStructureInOutBuffer<uint>())
                {
                    ProcessDepStatus ret = new ProcessDepStatus();
                    NtStatus status = NtSystemCalls.NtQueryInformationProcess(Handle, ProcessInformationClass.ProcessExecuteFlags, buffer, buffer.Length, out int return_length);
                    if (!status.IsSuccess())
                    {
                        if (status != NtStatus.STATUS_INVALID_PARAMETER)
                        {
                            status.ToNtException();
                        }
                        else if (Is64Bit)
                        {
                            // On 64 bits OS, DEP is always ON for 64 bits processes
                            ret.Enabled = true;
                            ret.Permanent = true;
                        }

                        return ret;
                    }

                    uint result = buffer.Result;
                    if ((result & 2) == 0)
                    {
                        ret.Enabled = true;
                        if ((result & 4) != 0)
                        {
                            ret.DisableAtlThunkEmulation = true;
                        }
                    }
                    if ((result & 8) != 0)
                    {
                        ret.Permanent = true;
                    }
                    return ret;
                }
            }
        }

        /// <summary>
        /// Get whether process has a debug port.
        /// </summary>
        /// <returns></returns>
        public bool HasDebugPort => Query<IntPtr>(ProcessInformationClass.ProcessDebugPort) != IntPtr.Zero;

        /// <summary>
        /// Get handle count.
        /// </summary>
        public int HandleCount =>
                // Weirdly if you query for 8 bytes it just returns count in upper and lower bits.
                Query<int>(ProcessInformationClass.ProcessHandleCount);

        /// <summary>
        /// Get break on termination flag.
        /// </summary>
        public bool BreakOnTermination => Query<int>(ProcessInformationClass.ProcessBreakOnTermination) != 0;

        /// <summary>
        /// Get or set debug flags.
        /// </summary>
        public ProcessDebugFlags DebugFlags
        {
            get => (ProcessDebugFlags)Query<int>(ProcessInformationClass.ProcessDebugFlags);
            set => Set(ProcessInformationClass.ProcessDebugFlags, (int)value);
        }

        /// <summary>
        /// Get or set execute flags.
        /// </summary>
        public ProcessExecuteFlags ExecuteFlags
        {
            get => (ProcessExecuteFlags)Query<int>(ProcessInformationClass.ProcessExecuteFlags);
            set => Set(ProcessInformationClass.ProcessExecuteFlags, (int)value);
        }

        /// <summary>
        /// Get IO priority.
        /// </summary>
        public int IoPriority => Query<int>(ProcessInformationClass.ProcessIoPriority);

        /// <summary>
        /// Get secure cookie.
        /// </summary>
        public int Cookie => Query<int>(ProcessInformationClass.ProcessCookie);

        /// <summary>
        /// Get the process user.
        /// </summary>
        public Sid User => GetUser();

        /// <summary>
        /// Get the integrity level of the process.
        /// </summary>
        public TokenIntegrityLevel IntegrityLevel => GetIntegrityLevel(true).Result;

        /// <summary>
        /// Get process mitigations
        /// </summary>
        public NtProcessMitigations Mitigations => new NtProcessMitigations(this);

        /// <summary>
        /// Get extended process flags.
        /// </summary>
        public ProcessExtendedBasicInformationFlags ExtendedFlags => GetExtendedBasicInfo(false).Flags;

        /// <summary>
        /// Get process window title (from Process Parameters).
        /// </summary>
        public string WindowTitle
        {
            get
            {
                using (var buf = QueryBuffer<ProcessWindowInformation>(ProcessInformationClass.ProcessWindowInformation))
                {
                    ProcessWindowInformation window_info = buf.Result;
                    return buf.Data.ReadUnicodeString(window_info.WindowTitleLength / 2);
                }
            }
        }

        /// <summary>
        /// Get process window flags (from Process Parameters).
        /// </summary>
        public uint WindowFlags
        {
            get
            {
                using (var buf = QueryBuffer<ProcessWindowInformation>(ProcessInformationClass.ProcessWindowInformation))
                {
                    return buf.Result.WindowFlags;
                }
            }
        }

        /// <summary>
        /// Get the process subsystem type.
        /// </summary>
        public ProcessSubsystemInformationType SubsystemType => (ProcessSubsystemInformationType)Query<int>(ProcessInformationClass.ProcessSubsystemInformation);

        /// <summary>
        /// Get if the process is Wow64
        /// </summary>
        public bool Wow64
        {
            get
            {
                if (!_wow64.HasValue)
                {
                    _wow64 = Query<IntPtr>(ProcessInformationClass.ProcessWow64Information) != IntPtr.Zero;
                }
                return _wow64.Value;
            }
        }

        /// <summary>
        /// Get whether the process is 64bit.
        /// </summary>
        public bool Is64Bit => Environment.Is64BitOperatingSystem && !Wow64;

        /// <summary>
        /// Get whether LUID device maps are enabled.
        /// </summary>
        public bool LUIDDeviceMapsEnabled => Query<int>(ProcessInformationClass.ProcessLUIDDeviceMapsEnabled) != 0;

        /// <summary>
        /// Return whether this process is sandboxed.
        /// </summary>
        public bool IsSandboxToken => QueryToken(token => token.IsSandbox);

        /// <summary>
        /// Get or set the hard error mode.
        /// </summary>
        public int HardErrorMode
        {
            get => Query(ProcessInformationClass.ProcessDefaultHardErrorMode, 0, false).GetResultOrDefault(0);
            set => Set(ProcessInformationClass.ProcessDefaultHardErrorMode, value);
        }


        /// <summary>
        /// Does the process has a child process restriction?
        /// </summary>
        public bool IsChildProcessRestricted
        {
            get
            {
                int policy = GetRawMitigationPolicy(ProcessMitigationPolicy.ChildProcess);
                if (policy != 0)
                {
                    return (policy & 1) == 1;
                }

                var result = Query(ProcessInformationClass.ProcessChildProcessInformation, new ProcessChildProcessRestricted(), false);
                if (result.IsSuccess)
                {
                    return result.Result.ProhibitChildProcesses != 0;
                }
                var result_1709 = Query(ProcessInformationClass.ProcessChildProcessInformation, new ProcessChildProcessRestricted1709(), false);
                if (result_1709.IsSuccess)
                {
                    return result_1709.Result.ProhibitChildProcesses != 0;
                }
                return false;
            }
        }

        /// <summary>
        /// Gets whether the process is currently deleting.
        /// </summary>
        public bool IsDeleting => ExtendedFlags.HasFlagSet(ProcessExtendedBasicInformationFlags.IsProcessDeleting);

        /// <summary>
        /// Gets whether the process is secure.
        /// </summary>
        public bool Secure => ExtendedFlags.HasFlagSet(ProcessExtendedBasicInformationFlags.IsSecureProcess);

        /// <summary>
        /// Gets whether the process is protected.
        /// </summary>
        public bool Protected => ExtendedFlags.HasFlagSet(ProcessExtendedBasicInformationFlags.IsProtectedProcess);

        /// <summary>
        /// Gets whether the process is a subsystem process.
        /// </summary>
        public bool Subsystem => ExtendedFlags.HasFlagSet(ProcessExtendedBasicInformationFlags.IsSubsystemProcess);

        /// <summary>
        /// Get process protection information.
        /// </summary>
        public PsProtection Protection => Query<PsProtection>(ProcessInformationClass.ProcessProtectionInformation);

        /// <summary>
        /// Query process section image information.
        /// </summary>
        public SectionImageInformation ImageInformation => Query<SectionImageInformation>(ProcessInformationClass.ProcessImageInformation);

        /// <summary>
        /// Get full image path name in native format
        /// </summary>
        public override string FullPath
        {
            get
            {
                var result = GetImageFilePath(true, false);
                if (result.IsSuccess)
                {
                    return result.Result;
                }
                if (_pid.HasValue || IsAccessGranted(ProcessAccessRights.QueryLimitedInformation))
                {
                    switch (ProcessId)
                    {
                        case 0:
                            return "Idle";
                        case 4:
                            return "System";
                        default:
                            return $"process:{ProcessId}";
                    }
                }

                return string.Empty;
            }
        }

        /// <summary>
        /// Get the Win32 image path.
        /// </summary>
        public string Win32ImagePath => GetImageFilePath(false, false).GetResultOrDefault() ?? string.Empty;

        /// <summary>
        /// Get owner process ID
        /// </summary>
        public int OwnerProcessId => Query<IntPtr>(ProcessInformationClass.ProcessConsoleHostProcess).ToInt32();

        /// <summary>
        /// Query the process token's full package name.
        /// </summary>
        public string PackageFullName => QueryToken(t => t.PackageFullName, string.Empty);

        /// <summary>
        /// Get or set whether resource virtualization is enabled.
        /// </summary>
        public bool VirtualizationEnabled
        {
            get => QueryToken(t => t.VirtualizationEnabled, false);
            set => Set(ProcessInformationClass.ProcessTokenVirtualizationEnabled, value ? 1 : 0);
        }

        /// <summary>
        /// Get the security domain of the process.
        /// </summary>
        public long SecurityDomain => GetSecurityDomain();

        /// <summary>
        /// Get the creation time of the process.
        /// </summary>
        public DateTime CreateTime => DateTime.FromFileTime(Query<KernelUserTimes>(ProcessInformationClass.ProcessTimes).CreateTime.QuadPart);
        /// <summary>
        /// Get the exit time of the process.
        /// </summary>
        public DateTime ExitTime => DateTime.FromFileTime(Query<KernelUserTimes>(ProcessInformationClass.ProcessTimes).ExitTime.QuadPart);
        /// <summary>
        /// Get the time spent in the kernel.
        /// </summary>
        public long KernelTime => Query<KernelUserTimes>(ProcessInformationClass.ProcessTimes).KernelTime.QuadPart;
        /// <summary>
        /// Get the time spent in user mode.
        /// </summary>
        public long UserTime => Query<KernelUserTimes>(ProcessInformationClass.ProcessTimes).UserTime.QuadPart;
        /// <summary>
        /// Get the time spent in the kernel in seconds.
        /// </summary>
        public double KernelTimeSeconds => new TimeSpan(KernelTime).TotalSeconds;
        /// <summary>
        /// Get the time spent in user mode.
        /// </summary>
        public double UserTimeSeconds => new TimeSpan(UserTime).TotalSeconds;
        /// <summary>
        /// Get the process IO counters.
        /// </summary>
        public IoCounters IoCounters => GetIoCounters(true).Result;
        /// <summary>
        /// Get or set priority boost disabled.
        /// </summary>
        public bool PriorityBoostDisabled
        {
            get => GetPriorityBoostDisabled(true).Result;
            set => SetPriorityBoostDisabled(value, true);
        }

        #endregion

        #region Static Properties

        /// <summary>
        /// Get the current process.
        /// </summary>
        /// <remarks>This only uses the pseudo handle, for the process. If you need a proper handle use OpenCurrent.</remarks>
        public static NtProcess Current => new NtProcess(new SafeKernelObjectHandle(-1));

        #endregion
    }
}
