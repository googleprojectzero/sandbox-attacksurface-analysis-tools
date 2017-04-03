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
        public static extern NtStatus NtQueryInformationJobObject(SafeKernelObjectHandle JobHandle, int JobInfoClass, IntPtr JobInformation, int JobInformationLength, out int ReturnLength);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtSetInformationJobObject(SafeKernelObjectHandle JobHandle, int JobInfoClass, IntPtr JobInformation, int JobInformationLength);
    }
#pragma warning restore 1591

    /// <summary>
    /// Class representing a NT Job object
    /// </summary>
    public class NtJob : NtObjectWithDuplicate<NtJob, GenericAccessRights>
    {
        internal NtJob(SafeKernelObjectHandle handle) : base(handle)
        {
        }

        /// <summary>
        /// Create a job object
        /// </summary>
        /// <param name="path">The path to the job object (can be null)</param>
        /// <param name="root">The root object when path is relative</param>
        /// <returns>The Job object</returns>
        public static NtJob Create(string path, NtObject root)
        {
            using (ObjectAttributes obja = new ObjectAttributes(path, AttributeFlags.CaseInsensitive, root))
            {
                SafeKernelObjectHandle handle;
                NtSystemCalls.NtCreateJobObject(out handle, JobAccessRights.MaximumAllowed, obja).ToNtException();
                return new NtJob(handle);
            }
        }

        /// <summary>
        /// Convert Job object into a Silo
        /// </summary>
        public void CreateSilo()
        {
            NtSystemCalls.NtSetInformationJobObject(Handle, 35, IntPtr.Zero, 0).ToNtException();
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
                SafeKernelObjectHandle handle;
                NtSystemCalls.NtOpenJobObject(out handle, desired_access, obja).ToNtException();
                return new NtJob(handle);
            }
        }
    }
}
