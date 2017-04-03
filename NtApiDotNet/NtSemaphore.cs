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
    /// <summary>
    /// Semaphore access rights.
    /// </summary>
    [Flags]
    public enum SemaphoreAccessRights : uint
    {
        None = 0,
        QueryState = 1,
        ModifyState = 2,
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
        public static extern NtStatus NtCreateSemaphore(out SafeKernelObjectHandle MutantHandle, SemaphoreAccessRights DesiredAccess,
            ObjectAttributes ObjectAttributes, int InitialCount, int MaximumCount);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtOpenSemaphore(out SafeKernelObjectHandle MutantHandle, SemaphoreAccessRights DesiredAccess,
            ObjectAttributes ObjectAttributes);


        [DllImport("ntdll.dll")]
        public static extern NtStatus NtReleaseSemaphore(
           SafeKernelObjectHandle SemaphoreHandle,
           int ReleaseCount,
           out int PreviousCount
        );
    }
#pragma warning restore 1591

    /// <summary>
    /// Class to represent a NT Semaphore object.
    /// </summary>
    public class NtSemaphore : NtObjectWithDuplicate<NtSemaphore, SemaphoreAccessRights>
    {
        internal NtSemaphore(SafeKernelObjectHandle handle) : base(handle)
        {
        }

        /// <summary>
        /// Create a semaphore object.
        /// </summary>
        /// <param name="object_attributes">The object attributes for the object</param>
        /// <param name="desired_access">The desired access for the object</param>
        /// <param name="initial_count">Initial count for semaphore</param>
        /// <param name="maximum_count">Maximum count for semaphore</param>
        /// <returns>The opened object</returns>
        public static NtSemaphore Create(ObjectAttributes object_attributes, SemaphoreAccessRights desired_access, int initial_count, int maximum_count)
        {
            SafeKernelObjectHandle handle;
            NtSystemCalls.NtCreateSemaphore(out handle, desired_access, object_attributes, initial_count, maximum_count).ToNtException();
            return new NtSemaphore(handle);
        }

        /// <summary>
        /// Create a semaphore object.
        /// </summary>
        /// <param name="path">The path to the object</param>
        /// <param name="root">The root if path is relative</param>
        /// <param name="initial_count">Initial count for semaphore</param>
        /// /// <param name="maximum_count">Maximum count for semaphore</param>
        /// <returns>The opened object</returns>
        public static NtSemaphore Create(string path, NtObject root, int initial_count, int maximum_count)
        {
            using (ObjectAttributes obja = new ObjectAttributes(path, AttributeFlags.CaseInsensitive, root))
            {
                return Create(obja, SemaphoreAccessRights.MaximumAllowed, initial_count, maximum_count);
            }
        }

        /// <summary>
        /// Open a semaphore object.
        /// </summary>
        /// <param name="object_attributes">The object attributes for the object</param>
        /// <param name="desired_access">The desired access for the object</param>
        /// <returns>The opened object</returns>
        public static NtSemaphore Open(ObjectAttributes object_attributes, SemaphoreAccessRights desired_access)
        {
            SafeKernelObjectHandle handle;
            NtSystemCalls.NtOpenSemaphore(out handle, desired_access, object_attributes).ToNtException();
            return new NtSemaphore(handle);
        }

        /// <summary>
        /// Open a semaphore object.
        /// </summary>
        /// <param name="path">The path to the object</param>
        /// <param name="root">The root if path is relative</param>
        /// <param name="desired_access">The desired access for the object</param>
        /// <returns>The opened object</returns>
        public static NtSemaphore Open(string path, NtObject root, SemaphoreAccessRights desired_access)
        {
            using (ObjectAttributes obja = new ObjectAttributes(path, AttributeFlags.CaseInsensitive, root))
            {
                return Open(obja, desired_access);
            }
        }

        /// <summary>
        /// Release the semaphore
        /// </summary>
        /// <param name="count">The release count</param>
        /// <returns>The previous count</returns>
        public int Release(int count)
        {
            int previous_count;
            NtSystemCalls.NtReleaseSemaphore(Handle, count, out previous_count).ToNtException();
            return previous_count;
        }
    }
}
