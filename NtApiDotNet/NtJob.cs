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
            NtSystemCalls.NtAssignProcessToJobObject(Handle, process.Handle).ToNtException();
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
        public void Terminate(NtStatus status)
        {
            NtSystemCalls.NtTerminateJobObject(Handle, status).ToNtException();
        }

        /// <summary>
        /// Set the limit flags for the job.
        /// </summary>
        /// <param name="flags">The limit flags.</param>
        public void SetLimitFlags(JobObjectLimitFlags flags)
        {
            if ((flags & JobObjectLimitFlags.Application) != 0)
            {
                JobObjectExtendedExtendedLimitInformation info = new JobObjectExtendedExtendedLimitInformation();
                info.ExtendedLimitInformation.BasicLimitInformation.LimitFlags = flags;
                Set(JobObjectInformationClass.JobObjectExtendedLimitInformation, info);
            }
            else
            {
                JobObjectExtendedLimitInformation info = new JobObjectExtendedLimitInformation();
                info.BasicLimitInformation.LimitFlags = flags;
                Set(JobObjectInformationClass.JobObjectExtendedLimitInformation, info);
            }
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
                int mask = ((int)JobObjectCompletionPortMessageFilters.MaxMessage - 1) - 1;
                int result = Query<int>(JobObjectInformationClass.JobObjectCompletionFilter);

                return (JobObjectCompletionPortMessageFilters)(~result & mask);
            }

            set
            {
                int filter = (int)value;
                Set(JobObjectInformationClass.JobObjectCompletionFilter, filter);
            }
        }

        /// <summary>
        /// Get or set the Maximum Bandwith NetRate limitation.
        /// </summary>
        [SupportedVersion(SupportedVersion.Windows10)]
        public ulong? MaxBandwidth
        {
            get
            {
                return GetNetRateValue(JobObjectNetRateControlFlags.MaxBandwidth, r => r.MaxBandwidth);
            }
            set
            {
                SetNetRateValue(value, JobObjectNetRateControlFlags.MaxBandwidth, (v, r) => { r.MaxBandwidth = v; return r; });
            }
        }

        /// <summary>
        /// Get or set the DSCP Tag NetRate limitation.
        /// </summary>
        [SupportedVersion(SupportedVersion.Windows10)]
        public byte? DscpTag
        {
            get
            {
                return GetNetRateValue(JobObjectNetRateControlFlags.DscpTag, r => r.DscpTag);
            }
            set
            {
                SetNetRateValue(value, JobObjectNetRateControlFlags.DscpTag, (v, r) => { r.DscpTag = v; return r; });
            }
        }

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
        #endregion
    }
}
