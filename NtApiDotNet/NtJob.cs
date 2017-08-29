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
#pragma warning disable 1591
    [Flags]
    public enum JobAccessRights : uint
    {
        None = 0,
        AssignProcess = 0x1,
        SetAttributes = 0x2,
        Query = 0x4,
        Terminate = 0x8,
        SetSecurityAttributes = 0x10,
        Impersonate = 0x20,
        GenericRead = GenericAccessRights.GenericRead,
        GenericWrite = GenericAccessRights.GenericWrite,
        GenericExecute = GenericAccessRights.GenericExecute,
        GenericAll = GenericAccessRights.GenericAll,
        Delete = GenericAccessRights.Delete,
        ReadControl = GenericAccessRights.ReadControl,
        WriteDac = GenericAccessRights.WriteDac,
        WriteOwner = GenericAccessRights.WriteOwner,
        Synchronize = GenericAccessRights.Synchronize,
        MaximumAllowed = GenericAccessRights.MaximumAllowed,
        AccessSystemSecurity = GenericAccessRights.AccessSystemSecurity
    }

    public enum JOBOBJECTINFOCLASS
    {
        JobObjectBasicAccountingInformation = 1,
        JobObjectBasicLimitInformation,
        JobObjectBasicProcessIdList,
        JobObjectBasicUIRestrictions,
        JobObjectSecurityLimitInformation,  // deprecated
        JobObjectEndOfJobTimeInformation,
        JobObjectAssociateCompletionPortInformation,
        JobObjectBasicAndIoAccountingInformation,
        JobObjectExtendedLimitInformation,
        JobObjectJobSetInformation,
        JobObjectGroupInformation,
        JobObjectNotificationLimitInformation,
        JobObjectLimitViolationInformation,
        JobObjectGroupInformationEx,
        JobObjectCpuRateControlInformation,
        JobObjectCompletionFilter,
        JobObjectCompletionCounter,
        JobObjectReserved1Information = 18,
        JobObjectReserved2Information,
        JobObjectReserved3Information,
        JobObjectReserved4Information,
        JobObjectReserved5Information,
        JobObjectReserved6Information,
        JobObjectReserved7Information,
        JobObjectReserved8Information,
        JobObjectReserved9Information,
        JobObjectReserved10Information,
        JobObjectReserved11Information,
        JobObjectReserved12Information,
        JobObjectReserved13Information,
        JobObjectReserved14Information = 31,
        JobObjectNetRateControlInformation,
        JobObjectNotificationLimitInformation2,
        JobObjectLimitViolationInformation2,
        JobObjectCreateSilo,
        JobObjectSiloBasicInformation,
        JobObjectReserved15Information = 37,
        JobObjectReserved16Information = 38,
        JobObjectReserved17Information = 39,
        JobObjectReserved18Information = 40,
        JobObjectReserved19Information = 41,
        JobObjectReserved20Information = 42,
        JobObjectReserved21Information = 43,
        JobObjectReserved22Information = 44,
        JobObjectReserved23Information = 45,
        JobObjectReserved24Information = 46,
        JobObjectReserved25Information = 47,
        MaxJobObjectInfoClass
    }

    public enum JobObjectCompletionPortMessages
    {
        EndOfJobTime         = 1,
        EndOfProcessTime     = 2,
        ActiveProcessLimit    = 3,
        ActiveProcessZero     = 4,
        Unknown5              = 5,
        NewProcess             = 6,
        ExitProcess            = 7,
        AbnormalExitProcess   = 8,
        ProcessMemoryLimit    = 9,
        JobMemoryLimit        = 10,
        NotificationLimit      = 11,
        JobCycleTimeLimit    = 12,
        SiloTerminated         = 13,
        MaxMessage = 14,
    }

    [Flags]
    public enum JobObjectCompletionPortMessageFilters
    {
        None = 0,
        EndOfJobTime = 1 << JobObjectCompletionPortMessages.EndOfJobTime,
        EndOfProcessTime = 1 << JobObjectCompletionPortMessages.EndOfProcessTime,
        ActiveProcessLimit = 1 << JobObjectCompletionPortMessages.ActiveProcessLimit,
        ActiveProcessZero = 1 << JobObjectCompletionPortMessages.ActiveProcessZero,
        Unknown5 = 1 << JobObjectCompletionPortMessages.Unknown5,
        NewProcess = 1 << JobObjectCompletionPortMessages.NewProcess,
        ExitProcess = 1 << JobObjectCompletionPortMessages.ExitProcess,
        AbnormalExitProcess = 1 << JobObjectCompletionPortMessages.AbnormalExitProcess,
        ProcessMemoryLimit = 1 << JobObjectCompletionPortMessages.ProcessMemoryLimit,
        JobMemoryLimit = 1 << JobObjectCompletionPortMessages.JobMemoryLimit,
        NotificationLimit = 1 << JobObjectCompletionPortMessages.NotificationLimit,
        JobCycleTimeLimit = 1 << JobObjectCompletionPortMessages.JobCycleTimeLimit,
        SiloTerminated = 1 << JobObjectCompletionPortMessages.SiloTerminated,
        MaxMessage = 1 << JobObjectCompletionPortMessages.MaxMessage
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct JobObjectAssociateCompletionPort
    {
        public IntPtr CompletionKey;
        public IntPtr CompletionPort;
    }

    public static partial class NtSystemCalls
    {
        [DllImport("ntdll.dll")]
        public static extern NtStatus NtCreateJobObject(out SafeKernelObjectHandle JobHandle, JobAccessRights DesiredAccess, [In] ObjectAttributes ObjectAttributes);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtOpenJobObject(out SafeKernelObjectHandle JobHandle, JobAccessRights DesiredAccess, [In] ObjectAttributes ObjectAttributes);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtAssignProcessToJobObject(SafeKernelObjectHandle JobHandle, SafeKernelObjectHandle ProcessHandle);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtTerminateJobObject(SafeKernelObjectHandle JobHandle, NtStatus ExitStatus);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtQueryInformationJobObject(SafeKernelObjectHandle JobHandle, JOBOBJECTINFOCLASS JobInfoClass, 
            SafeBuffer JobInformation, int JobInformationLength, out int ReturnLength);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtSetInformationJobObject(SafeKernelObjectHandle JobHandle, JOBOBJECTINFOCLASS JobInfoClass, 
            SafeBuffer JobInformation, int JobInformationLength);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtIsProcessInJob(
            SafeKernelObjectHandle ProcessHandle,
            SafeKernelObjectHandle JobHandle
        );
    }
#pragma warning restore 1591

    /// <summary>
    /// Class representing a NT Job object
    /// </summary>
    [NtType("Job")]
    public class NtJob : NtObjectWithDuplicate<NtJob, JobAccessRights>
    {
        internal NtJob(SafeKernelObjectHandle handle) : base(handle)
        {
        }

        /// <summary>
        /// Create a job object
        /// </summary>
        /// <param name="object_attributes">The object attributes</param>
        /// <param name="desired_access">Desired access for job.</param>
        /// <param name="throw_on_error">True to throw an exception on error.</param>
        /// <returns>The NT status code and object result.</returns>
        public static NtResult<NtJob> Create(ObjectAttributes object_attributes, JobAccessRights desired_access, bool throw_on_error)
        {
            SafeKernelObjectHandle handle;
            return NtSystemCalls.NtCreateJobObject(out handle, JobAccessRights.MaximumAllowed, object_attributes).CreateResult(throw_on_error, () => new NtJob(handle));
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
        /// Convert Job object into a Silo
        /// </summary>
        public void CreateSilo()
        {
            NtSystemCalls.NtSetInformationJobObject(Handle, JOBOBJECTINFOCLASS.JobObjectCreateSilo, 
                SafeHGlobalBuffer.Null, 0).ToNtException();
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

        internal static NtResult<NtObject> FromName(ObjectAttributes object_attributes, AccessMask desired_access, bool throw_on_error)
        {
            return Open(object_attributes, desired_access.ToSpecificAccess<JobAccessRights>(), throw_on_error).Cast<NtObject>();
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

        /// <summary>
        /// Assign a process to this job object.
        /// </summary>
        /// <param name="process">The process to assign.</param>
        public void AssignProcess(NtProcess process)
        {
            NtSystemCalls.NtAssignProcessToJobObject(Handle, process.Handle).ToNtException();
        }

        private void SetInfo<T>(JOBOBJECTINFOCLASS info_class, T value) where T : new()
        {
            using (var buffer = value.ToBuffer())
            {
                NtSystemCalls.NtSetInformationJobObject(Handle, info_class, buffer, buffer.Length);
            }
        }

        private T QueryInfoFixed<T>(JOBOBJECTINFOCLASS info_class) where T : new()
        {
            using (var buffer = new SafeStructureInOutBuffer<T>())
            {
                int ret_length;
                NtSystemCalls.NtQueryInformationJobObject(Handle, info_class, buffer, buffer.Length, out ret_length).ToNtException();
                return buffer.Result;
            }
        }

        /// <summary>
        /// Associate a completion port with the job.
        /// </summary>
        /// <param name="port">The completion port.</param>
        /// <param name="key">The key associated with the port.</param>
        public void AssociateCompletionPort(NtIoCompletion port, IntPtr key)
        {
            JobObjectAssociateCompletionPort info = new JobObjectAssociateCompletionPort();
            info.CompletionKey = key;
            info.CompletionPort = port.Handle.DangerousGetHandle();
            SetInfo(JOBOBJECTINFOCLASS.JobObjectAssociateCompletionPortInformation, info);
        }
        
        /// <summary>
        /// Get or set completion filter for job object.
        /// </summary>
        public JobObjectCompletionPortMessageFilters CompletionFilter
        {
            get
            {
                int mask = ((int)JobObjectCompletionPortMessageFilters.MaxMessage - 1) - 1;
                int result = QueryInfoFixed<int>(JOBOBJECTINFOCLASS.JobObjectCompletionFilter);

                return (JobObjectCompletionPortMessageFilters)(~result & mask);
            }

            set
            {
                int filter = (int)value;
                SetInfo(JOBOBJECTINFOCLASS.JobObjectCompletionFilter, filter);
            }
        }

        /// <summary>
        /// Terminate this job object.
        /// </summary>
        /// <param name="status">The termination status.</param>
        public void Terminate(NtStatus status)
        {
            NtSystemCalls.NtTerminateJobObject(Handle, status).ToNtException();
        }
    }
}
