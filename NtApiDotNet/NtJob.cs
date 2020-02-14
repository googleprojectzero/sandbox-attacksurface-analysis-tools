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
using System.Linq;
using System.Runtime.InteropServices;

namespace NtApiDotNet
{
    /// <summary>
    /// Class representing a NT Job object
    /// </summary>
    [NtType("Job")]
    public class NtJob : NtObjectWithDuplicateAndInfo<NtJob, JobAccessRights, JobObjectInformationClass, JobObjectInformationClass>
    {
        #region Constructors
        internal NtJob(SafeKernelObjectHandle handle) : base(handle)
        {
        }

        internal sealed class NtTypeFactoryImpl : NtTypeFactoryImplBase
        {
            public NtTypeFactoryImpl() : base(true)
            {
            }

            protected override sealed NtResult<NtJob> OpenInternal(ObjectAttributes obj_attributes,
                JobAccessRights desired_access, bool throw_on_error)
            {
                return NtJob.Open(obj_attributes, desired_access, throw_on_error);
            }
        }

        #endregion

        #region Static Methods
        /// <summary>
        /// Create a job object
        /// </summary>
        /// <param name="object_attributes">The object attributes</param>
        /// <param name="desired_access">Desired access for job.</param>
        /// <param name="throw_on_error">True to throw an exception on error.</param>
        /// <returns>The NT status code and object result.</returns>
        public static NtResult<NtJob> Create(ObjectAttributes object_attributes, JobAccessRights desired_access, bool throw_on_error)
        {
            return NtSystemCalls.NtCreateJobObject(out SafeKernelObjectHandle handle, desired_access, object_attributes)
                .CreateResult(throw_on_error, () => new NtJob(handle));
        }

        /// <summary>
        /// Create a job object
        /// </summary>
        /// <param name="object_attributes">The object attributes</param>
        /// <param name="desired_access">Desired access for job.</param>
        /// <returns>The Job object.</returns>
        public static NtJob Create(ObjectAttributes object_attributes, JobAccessRights desired_access)
        {
            return Create(object_attributes, desired_access, true).Result;
        }

        /// <summary>
        /// Create a job object
        /// </summary>
        /// <param name="path">The path to the job object (can be null)</param>
        /// <param name="root">The root object when path is relative</param>
        /// <param name="desired_access">Desired access for job.</param>
        /// <returns>The Job object</returns>
        public static NtJob Create(string path, NtObject root, JobAccessRights desired_access)
        {
            using (ObjectAttributes obj_attr = new ObjectAttributes(path, AttributeFlags.CaseInsensitive, root))
            {
                return Create(obj_attr, desired_access);
            }
        }

        /// <summary>
        /// Create a job object
        /// </summary>
        /// <param name="path">The path to the job object (can be null)</param>
        /// <param name="root">The root object when path is relative</param>
        /// <returns>The Job object</returns>
        public static NtJob Create(string path, NtObject root)
        {
            return Create(path, root, JobAccessRights.MaximumAllowed);
        }

        /// <summary>
        /// Create an unnamed job object
        /// </summary>
        /// <returns>The Job object</returns>
        public static NtJob Create()
        {
            return Create(null, null);
        }

        /// <summary>
        /// Open a job object
        /// </summary>
        /// <param name="object_attributes">The object attributes</param>
        /// <param name="desired_access">Desired access for job.</param>
        /// <param name="throw_on_error">True to throw an exception on error.</param>
        /// <returns>The NT status code and object result.</returns>
        public static NtResult<NtJob> Open(ObjectAttributes object_attributes, JobAccessRights desired_access, bool throw_on_error)
        {
            SafeKernelObjectHandle handle;
            return NtSystemCalls.NtOpenJobObject(out handle, desired_access, object_attributes).CreateResult(throw_on_error, () => new NtJob(handle));
        }

        /// <summary>
        /// Open a job object
        /// </summary>
        /// <param name="object_attributes">The object attributes</param>
        /// <param name="desired_access">Desired access for job.</param>
        /// <returns>The Job object</returns>
        public static NtJob Open(ObjectAttributes object_attributes, JobAccessRights desired_access)
        {
            return Open(object_attributes, desired_access, true).Result;
        }

        /// <summary>
        /// Open a job object
        /// </summary>
        /// <param name="path">The path to the job object</param>
        /// <param name="root">The root object when path is relative</param>
        /// <param name="desired_access">Desired access for the job object</param>
        /// <returns>The Job object</returns>
        public static NtJob Open(string path, NtObject root, JobAccessRights desired_access)
        {
            using (ObjectAttributes obja = new ObjectAttributes(path, AttributeFlags.CaseInsensitive, root))
            {
                return Open(obja, desired_access);
            }
        }

        /// <summary>
        /// Open a job object
        /// </summary>
        /// <param name="path">The path to the job object</param>
        /// <param name="root">The root object when path is relative</param>
        /// <returns>The Job object</returns>
        public static NtJob Open(string path, NtObject root)
        {
            return Open(path, root, JobAccessRights.MaximumAllowed);
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Convert Job object into a Silo
        /// </summary>
        public void CreateSilo()
        {
            NtSystemCalls.NtSetInformationJobObject(Handle, JobObjectInformationClass.JobObjectCreateSilo,
                SafeHGlobalBuffer.Null, 0).ToNtException();
        }

        /// <summary>
        /// Assign a process to this job object.
        /// </summary>
        /// <param name="process">The process to assign.</param>
        public void AssignProcess(NtProcess process)
        {
            AssignProcess(process, true);
        }

        /// <summary>
        /// Assign a process to this job object.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <param name="process">The process to assign.</param>
        /// <returns>The NT status code.</returns>
        public NtStatus AssignProcess(NtProcess process, bool throw_on_error)
        {
            return NtSystemCalls.NtAssignProcessToJobObject(Handle, process.Handle).ToNtException(throw_on_error);
        }

        /// <summary>
        /// Assign a process to this job object using current Job on Windows 1709+.
        /// </summary>
        public void AssignProcessPseudoHandle()
        {
            AssignProcess(NtProcess.FromHandle(new SafeKernelObjectHandle(new IntPtr(-7), false)));
        }

        /// <summary>
        /// Associate a completion port with the job.
        /// </summary>
        /// <param name="port">The completion port.</param>
        /// <param name="key">The key associated with the port.</param>
        public void AssociateCompletionPort(NtIoCompletion port, IntPtr key)
        {
            JobObjectAssociateCompletionPort info = new JobObjectAssociateCompletionPort
            {
                CompletionKey = key,
                CompletionPort = port.Handle.DangerousGetHandle()
            };
            Set(JobObjectInformationClass.JobObjectAssociateCompletionPortInformation, info);
        }

        /// <summary>
        /// Terminate this job object.
        /// </summary>
        /// <param name="status">The termination status.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public NtStatus Terminate(NtStatus status, bool throw_on_error)
        {
            return NtSystemCalls.NtTerminateJobObject(Handle, status).ToNtException(throw_on_error);
        }

        /// <summary>
        /// Terminate this job object.
        /// </summary>
        /// <param name="status">The termination status.</param>
        public void Terminate(NtStatus status)
        {
            Terminate(status, true);
        }

        /// <summary>
        /// Set the limit flags for the job.
        /// </summary>
        /// <param name="flags">The limit flags.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public NtStatus SetLimitFlags(JobObjectLimitFlags flags, bool throw_on_error)
        {
            if (flags.HasFlag(JobObjectLimitFlags.Application))
            {
                return SetExtendedLimitInformationV2(i => {
                    i.BasicLimitInformation.LimitFlags = flags;
                    return i;
                }, throw_on_error);
            }
            else
            {
                return SetExtendedLimitInformation(i => {
                    i.BasicLimitInformation.LimitFlags = flags;
                    return i;
                }, throw_on_error);
            }
        }

        /// <summary>
        /// Set the limit flags for the job.
        /// </summary>
        /// <param name="flags">The limit flags.</param>
        public void SetLimitFlags(JobObjectLimitFlags flags)
        {
            SetLimitFlags(flags, true);
        }

        /// <summary>
        /// Set the Silo system root directory.
        /// </summary>
        /// <param name="system_root">The absolute path to the system root directory.</param>
        /// <remarks>The system_root path must start with a capital drive letter and not end with a backslash.</remarks>
        public void SetSiloSystemRoot(string system_root)
        {
            Set(JobObjectInformationClass.JobObjectSiloSystemRoot, new UnicodeStringIn(system_root));
        }

        /// <summary>
        /// Set the active process limit.
        /// </summary>
        /// <param name="active_process_limit">The number of active processes in the job.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public NtStatus SetActiveProcessLimit(int active_process_limit, bool throw_on_error)
        {
            return SetExtendedLimitInformation(i => {
                i.BasicLimitInformation.ActiveProcessLimit = active_process_limit;
                i.BasicLimitInformation.LimitFlags |= JobObjectLimitFlags.ActiveProcess;
                return i;
            }, throw_on_error);
        }

        /// <summary>
        /// Set the active process limit.
        /// </summary>
        /// <param name="active_process_limit">The number of active processes in the job.</param>
        public void SetActiveProcessLimit(int active_process_limit)
        {
            SetActiveProcessLimit(active_process_limit, true);
        }

        /// <summary>
        /// Set minimum and maximum working set size.
        /// </summary>
        /// <param name="minimum_working_set_size">The minimum working set size.</param>
        /// <param name="maximum_working_set_size">The maximum working set size.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public NtStatus SetWorkingSetSize(long minimum_working_set_size, long maximum_working_set_size, bool throw_on_error)
        {
            return SetExtendedLimitInformation(i => {
                i.BasicLimitInformation.MinimumWorkingSetSize = new IntPtr(minimum_working_set_size);
                i.BasicLimitInformation.MaximumWorkingSetSize = new IntPtr(maximum_working_set_size);
                i.BasicLimitInformation.LimitFlags |= JobObjectLimitFlags.WorkingSet;
                return i;
            }, throw_on_error);
        }

        /// <summary>
        /// Set minimum and maximum working set size.
        /// </summary>
        /// <param name="minimum_working_set_size">The minimum working set size.</param>
        /// <param name="maximum_working_set_size">The maximum working set size.</param>
        public void SetWorkingSetSize(long minimum_working_set_size, long maximum_working_set_size)
        {
            SetWorkingSetSize(minimum_working_set_size, maximum_working_set_size, true);
        }

        /// <summary>
        /// Set the process memory limit.
        /// </summary>
        /// <param name="process_memory_limit">The memory limit for a process.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public NtStatus SetProcessMemoryLimit(long process_memory_limit, bool throw_on_error)
        {
            return SetExtendedLimitInformation(i => {
                i.ProcessMemoryLimit = new IntPtr(process_memory_limit);
                i.BasicLimitInformation.LimitFlags |= JobObjectLimitFlags.ProcessMemory;
                return i;
            }, throw_on_error);
        }

        /// <summary>
        /// Set the process memory limit.
        /// </summary>
        /// <param name="process_memory_limit">The memory limit for a process.</param>
        /// <returns>The NT status code.</returns>
        public void SetProcessMemoryLimit(long process_memory_limit)
        {
            SetProcessMemoryLimit(process_memory_limit, true);
        }

        /// <summary>
        /// Set the job memory limit.
        /// </summary>
        /// <param name="job_memory_limit">The memory limit for a job.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public NtStatus SetJobMemoryLimit(long job_memory_limit, bool throw_on_error)
        {
            return SetExtendedLimitInformation(i => {
                i.JobMemoryLimit = new IntPtr(job_memory_limit);
                i.BasicLimitInformation.LimitFlags |= JobObjectLimitFlags.JobMemory;
                return i;
            }, throw_on_error);
        }

        /// <summary>
        /// Set the job memory limit.
        /// </summary>
        /// <param name="process_memory_limit">The memory limit for a job.</param>
        /// <returns>The NT status code.</returns>
        public void SetJobMemoryLimit(long process_memory_limit)
        {
            SetJobMemoryLimit(process_memory_limit, true);
        }

        /// <summary>
        /// Set the time limit for a process.
        /// </summary>
        /// <param name="process_time_limit">The time limit for a process, in 100ns ticks.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public NtStatus SetProcessTimeLimit(long process_time_limit, bool throw_on_error)
        {
            return SetExtendedLimitInformation(i => {
                i.BasicLimitInformation.PerProcessUserTimeLimit = new LargeIntegerStruct() { QuadPart = process_time_limit };
                i.BasicLimitInformation.LimitFlags |= JobObjectLimitFlags.ProcessTime;
                return i;
            }, throw_on_error);
        }

        /// <summary>
        /// Set the time limit for a process.
        /// </summary>
        /// <param name="process_time_limit">The time limit for a process, in 100ns ticks.</param>
        public void SetProcessTimeLimit(long process_time_limit)
        {
            SetProcessTimeLimit(process_time_limit, true);
        }

        /// <summary>
        /// Set the time limit for a job.
        /// </summary>
        /// <param name="job_time_limit">The time limit for a job, in 100ns ticks.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public NtStatus SetJobTimeLimit(long job_time_limit, bool throw_on_error)
        {
            return SetExtendedLimitInformation(i => {
                i.BasicLimitInformation.PerJobUserTimeLimit = new LargeIntegerStruct() { QuadPart = job_time_limit };
                i.BasicLimitInformation.LimitFlags |= JobObjectLimitFlags.JobTime;
                return i;
            }, throw_on_error);
        }

        /// <summary>
        /// Set the time limit for a job.
        /// </summary>
        /// <param name="job_time_limit">The time limit for a job, in 100ns ticks.</param>
        public void SetJobTimeLimit(long job_time_limit)
        {
            SetProcessTimeLimit(job_time_limit, true);
        }

        /// <summary>
        /// Get list of process IDs in Job.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The list of process IDs.</returns>
        public NtResult<IEnumerable<int>> GetProcessIdList(bool throw_on_error)
        {
            using (var buffer = QueryBuffer(JobObjectInformationClass.JobObjectBasicProcessIdList, new JobObjectBasicProcessIdList(), throw_on_error))
            {
                if (!buffer.IsSuccess)
                {
                    return buffer.Cast<IEnumerable<int>>();
                }
                var info = buffer.Result.Result;
                IntPtr[] ret = new IntPtr[info.NumberOfProcessIdsInList];
                buffer.Result.Data.ReadArray(0, ret, 0, ret.Length);
                return ret.Select(i => i.ToInt32()).CreateResult();
            }
        }

        /// <summary>
        /// Get list of process IDs in Job.
        /// </summary>
        /// <returns>The list of process IDs.</returns>
        public IEnumerable<int> GetProcessIdList()
        {
            return GetProcessIdList(true).Result;
        }

        /// <summary>
        /// Set UI Restriction Flags.
        /// </summary>
        /// <param name="flags">The UI Restriction Flags.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public NtStatus SetUiRestrictionFlags(JobObjectUiLimitFlags flags, bool throw_on_error)
        {
            return Set(JobObjectInformationClass.JobObjectBasicUIRestrictions, (int)flags, throw_on_error);
        }

        /// <summary>
        /// Set UI Restriction Flags.
        /// </summary>
        /// <param name="flags">The UI Restriction Flags.</param>
        /// <returns>The NT status code.</returns>
        public void SetUiRestrictionFlags(JobObjectUiLimitFlags flags)
        {
            SetUiRestrictionFlags(flags, true);
        }

        /// <summary>
        /// Method to query information for this object type.
        /// </summary>
        /// <param name="info_class">The information class.</param>
        /// <param name="buffer">The buffer to return data in.</param>
        /// <param name="return_length">Return length from the query.</param>
        /// <returns>The NT status code for the query.</returns>
        public override NtStatus QueryInformation(JobObjectInformationClass info_class, SafeBuffer buffer, out int return_length)
        {
            return NtSystemCalls.NtQueryInformationJobObject(Handle, info_class, buffer, buffer.GetLength(), out return_length);
        }

        /// <summary>
        /// Method to set information for this object type.
        /// </summary>
        /// <param name="info_class">The information class.</param>
        /// <param name="buffer">The buffer to set data from.</param>
        /// <returns>The NT status code for the set.</returns>
        public override NtStatus SetInformation(JobObjectInformationClass info_class, SafeBuffer buffer)
        {
            return NtSystemCalls.NtSetInformationJobObject(Handle, info_class, buffer, buffer.GetLength());
        }

        #endregion

        #region Public Properties
        /// <summary>
        /// Get or set completion filter for job object.
        /// </summary>
        public JobObjectCompletionPortMessageFilters CompletionFilter
        {
            get
            {
                return (JobObjectCompletionPortMessageFilters)Query<int>
                    (JobObjectInformationClass.JobObjectCompletionFilter);
            }

            set
            {
                int filter = (int)value;
                Set(JobObjectInformationClass.JobObjectCompletionFilter, filter);
            }
        }

        /// <summary>
        /// The count of completions for the job.
        /// </summary>
        public long CompletionCounter => Query<long>(JobObjectInformationClass.JobObjectCompletionCounter);

        /// <summary>
        /// Get or set the Maximum Bandwith NetRate limitation.
        /// </summary>
        [SupportedVersion(SupportedVersion.Windows10)]
        public ulong? MaxBandwidth
        {
            get => GetNetRateValue(JobObjectNetRateControlFlags.MaxBandwidth, r => r.MaxBandwidth);
            set => SetNetRateValue(value, JobObjectNetRateControlFlags.MaxBandwidth, (v, r) => { r.MaxBandwidth = v; return r; });
        }

        /// <summary>
        /// Get or set the DSCP Tag NetRate limitation.
        /// </summary>
        [SupportedVersion(SupportedVersion.Windows10)]
        public byte? DscpTag
        {
            get => GetNetRateValue(JobObjectNetRateControlFlags.DscpTag, r => r.DscpTag);
            set => SetNetRateValue(value, JobObjectNetRateControlFlags.DscpTag, (v, r) => { r.DscpTag = v; return r; });
        }

        /// <summary>
        /// Get or set the active process limit.
        /// </summary>
        public int ActiveProcessLimit
        {
            get => GetExtendedLimitInfo().BasicLimitInformation.ActiveProcessLimit;
            set => SetActiveProcessLimit(value, true);
        }

        /// <summary>
        /// Get or set the minimum working set size.
        /// </summary>
        public long MinimumWorkingSetSize
        {
            get => GetExtendedLimitInfo().BasicLimitInformation.MinimumWorkingSetSize.ToInt64();
            set => SetWorkingSetSize(value, MaximumWorkingSetSize, true);
        }

        /// <summary>
        /// Get or set the maximum working set size.
        /// </summary>
        public long MaximumWorkingSetSize
        {
            get => GetExtendedLimitInfo().BasicLimitInformation.MaximumWorkingSetSize.ToInt64();
            set => SetWorkingSetSize(MinimumWorkingSetSize, value, true);
        }

        /// <summary>
        /// Get or set the process time limit.
        /// </summary>
        public long ProcessTime
        {
            get => GetExtendedLimitInfo().BasicLimitInformation.PerProcessUserTimeLimit.QuadPart;
            set => SetProcessTimeLimit(value, true);
        }

        /// <summary>
        /// Get or set the process time limit.
        /// </summary>
        public long JobTime
        {
            get => GetExtendedLimitInfo().BasicLimitInformation.PerJobUserTimeLimit.QuadPart;
            set => SetJobTimeLimit(value, true);
        }

        /// <summary>
        /// Get or set the process memory limit.
        /// </summary>
        public long ProcessMemory
        {
            get => GetExtendedLimitInfo().ProcessMemoryLimit.ToInt64();
            set => SetProcessMemoryLimit(value, true);
        }

        /// <summary>
        /// Get or set the process memory limit.
        /// </summary>
        public long JobMemory
        {
            get => GetExtendedLimitInfo().JobMemoryLimit.ToInt64();
            set => SetJobMemoryLimit(value, true);
        }

        /// <summary>
        /// Get used peak job memory used.
        /// </summary>
        public long PeakJobMemoryUsed => GetExtendedLimitInfo().PeakJobMemoryUsed.ToInt64();

        /// <summary>
        /// Get used peak job memory used.
        /// </summary>
        public long PeakProcessMemoryUsed => GetExtendedLimitInfo().PeakProcessMemoryUsed.ToInt64();

        /// <summary>
        /// Get or set the job limit flags.
        /// </summary>
        public JobObjectLimitFlags LimitFlags
        {
            get => GetExtendedLimitInfo().BasicLimitInformation.LimitFlags;
            set => SetLimitFlags(value);
        }

        /// <summary>
        /// Get or set the job UI Restriction flags.
        /// </summary>
        public JobObjectUiLimitFlags UiRestrictionFlags
        {
            get => (JobObjectUiLimitFlags)Query<int>(JobObjectInformationClass.JobObjectBasicUIRestrictions);
            set => SetUiRestrictionFlags(value);
        }

        /// <summary>
        /// Get or set whether job breakaway is allowed.
        /// </summary>
        public bool BreakawayOk
        {
            get => (LimitFlags & JobObjectLimitFlags.BreakawayOk) == JobObjectLimitFlags.BreakawayOk;
            set
            {
                if (value)
                {
                    LimitFlags |= JobObjectLimitFlags.BreakawayOk;
                }
                else
                {
                    LimitFlags &= ~JobObjectLimitFlags.BreakawayOk;
                }
            }
        }

        /// <summary>
        /// Get or set whether silenty job breakaway is allowed.
        /// </summary>
        public bool SilentBreakawayOk
        {
            get => (LimitFlags & JobObjectLimitFlags.SilentBreakawayOk) == JobObjectLimitFlags.SilentBreakawayOk;
            set
            {
                if (value)
                {
                    LimitFlags |= JobObjectLimitFlags.SilentBreakawayOk;
                }
                else
                {
                    LimitFlags &= ~JobObjectLimitFlags.SilentBreakawayOk;
                }
            }
        }

        /// <summary>
        /// ID of container.
        /// </summary>
        public Guid ContainerId => Query<JobObjectContainerIdentifierV2>(JobObjectInformationClass.JobObjectContainerId).ContainerId;

        /// <summary>
        /// ID of container telemetry.
        /// </summary>
        public Guid ContainerTelemetryId => Query<JobObjectContainerIdentifierV2>(JobObjectInformationClass.JobObjectContainerId).ContainerTelemetryId;

        /// <summary>
        /// Job ID.
        /// </summary>
        public int JobId => Query<JobObjectContainerIdentifierV2>(JobObjectInformationClass.JobObjectContainerId).JobId;

        #endregion

        #region Private Members
        private JobObjectNetRateControlInformation GetNetRateControlInformation()
        {
            return Query<JobObjectNetRateControlInformation>(JobObjectInformationClass.JobObjectNetRateControlInformation);
        }

        private T? GetNetRateValue<T>(JobObjectNetRateControlFlags enable_flag, 
            Func<JobObjectNetRateControlInformation, T> callback) where T : struct
        {
            var result = GetNetRateControlInformation();
            if (result.ControlFlags.HasFlag(JobObjectNetRateControlFlags.Enable)
                && result.ControlFlags.HasFlag(enable_flag))
            {
                return callback(result);
            }
            return null;
        }

        private void SetNetRateValue<T>(T? value, JobObjectNetRateControlFlags enable_flag, 
            Func<T, JobObjectNetRateControlInformation, JobObjectNetRateControlInformation> update_func) where T : struct
        {
            var result = GetNetRateControlInformation();
            if (value.HasValue)
            {
                result = update_func(value.Value, result);
                result.ControlFlags |= JobObjectNetRateControlFlags.Enable | enable_flag;
            }
            else
            {
                result.ControlFlags &= ~enable_flag;
                if (result.ControlFlags == JobObjectNetRateControlFlags.Enable)
                {
                    result.ControlFlags = JobObjectNetRateControlFlags.None;
                }
            }
            Set(JobObjectInformationClass.JobObjectNetRateControlInformation, result);
        }

        private NtStatus SetLimitInformation<T>(JobObjectInformationClass info_class, Func<T, T> set_limit, bool throw_on_error) where T : struct
        {
            var result = Query(info_class, default(T), throw_on_error);
            if (!result.IsSuccess)
                return result.Status;
            var info = result.Result;

            info = set_limit(info);
            return Set(info_class, info, throw_on_error);
        }

        private NtStatus SetExtendedLimitInformation(Func<JobObjectExtendedLimitInformation, JobObjectExtendedLimitInformation> set_limit, bool throw_on_error)
        {
            return SetLimitInformation(JobObjectInformationClass.JobObjectExtendedLimitInformation, set_limit, throw_on_error);
        }

        private NtStatus SetExtendedLimitInformationV2(Func<JobObjectExtendedLimitInformationV2, JobObjectExtendedLimitInformationV2> set_limit, bool throw_on_error)
        {
            return SetLimitInformation(JobObjectInformationClass.JobObjectExtendedLimitInformation, set_limit, throw_on_error);
        }

        private JobObjectExtendedLimitInformation GetExtendedLimitInfo()
        {
            return Query<JobObjectExtendedLimitInformation>(JobObjectInformationClass.JobObjectExtendedLimitInformation);
        }

        #endregion
    }
}
