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

using System.Runtime.InteropServices;

namespace NtApiDotNet
{
#pragma warning disable 1591
    public enum RegistryTransactionAccessRights : uint
    {
        QueryInformation = 0x01,
        SetInformation = 0x02,
        Enlist = 0x04,
        Commit = 0x08,
        Rollback = 0x10,
        Propagate = 0x20,
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
        public static extern NtStatus NtCreateRegistryTransaction(out SafeKernelObjectHandle Handle, RegistryTransactionAccessRights DesiredAccess,
            ObjectAttributes ObjectAttributes, int Flags);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtOpenRegistryTransaction(out SafeKernelObjectHandle Handle, RegistryTransactionAccessRights DesiredAccess,
            ObjectAttributes ObjectAttributes);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtCommitRegistryTransaction(SafeKernelObjectHandle Handle, int Flags);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtRollbackRegistryTransaction(SafeKernelObjectHandle Handle, int Flags);        
    }
#pragma warning restore 1591

    /// <summary>
    /// Class to represent a registry transaction object
    /// </summary>
    public class NtRegistryTransaction : NtObjectWithDuplicate<NtRegistryTransaction, RegistryTransactionAccessRights>
    {
        internal NtRegistryTransaction(SafeKernelObjectHandle handle) : base(handle)
        {
        }

        /// <summary>
        /// Create a transaction
        /// </summary>
        /// <param name="object_attributes">The object attributes</param>
        /// <param name="desired_access">Desired access for the handle</param>
        /// <returns>The opened transaction</returns>
        public static NtRegistryTransaction Create(ObjectAttributes object_attributes, RegistryTransactionAccessRights desired_access)
        {
            SafeKernelObjectHandle handle;
            NtSystemCalls.NtCreateRegistryTransaction(out handle,
                desired_access, object_attributes, 0).ToNtException();
            return new NtRegistryTransaction(handle);
        }

        /// <summary>
        /// Create a transaction
        /// </summary>
        /// <param name="path">The path of the transaction</param>
        /// <param name="root">The root if path is relative</param>
        /// <returns>The opened transaction</returns>
        public static NtRegistryTransaction Create(string path, NtObject root)
        {
            using (ObjectAttributes obja = new ObjectAttributes(path, AttributeFlags.CaseInsensitive, root))
            {
                return Create(obja, RegistryTransactionAccessRights.MaximumAllowed);
            }
        }

        /// <summary>
        /// Create a transaction
        /// </summary>
        /// <param name="path">The path of the transaction</param>
        /// <returns>The opened transaction</returns>
        public static NtRegistryTransaction Create(string path)
        {
            return Create(path, null);
        }

        /// <summary>
        /// Create a transaction
        /// </summary>
        /// <returns>The opened transaction</returns>
        public static NtRegistryTransaction Create()
        {
            return Create(null, null);
        }

        /// <summary>
        /// Open a transaction object.
        /// </summary>
        /// <param name="path">The path to the object</param>
        /// <param name="root">The root if path is relative</param>
        /// <param name="desired_access">The desired access for the object</param>
        /// <returns>The opened object</returns>
        public static NtRegistryTransaction Open(string path, NtObject root, RegistryTransactionAccessRights desired_access)
        {
            using (ObjectAttributes obja = new ObjectAttributes(path, AttributeFlags.CaseInsensitive, root))
            {
                return Open(obja, desired_access);
            }
        }

        /// <summary>
        /// Open a transaction object.
        /// </summary>
        /// <param name="object_attributes">The object attributes for the object</param>
        /// <param name="desired_access">The desired access for the object</param>
        /// <returns>The opened object</returns>
        public static NtRegistryTransaction Open(ObjectAttributes object_attributes, RegistryTransactionAccessRights desired_access)
        {
            SafeKernelObjectHandle handle;
            NtSystemCalls.NtOpenRegistryTransaction(out handle, desired_access, object_attributes).ToNtException();
            return new NtRegistryTransaction(handle);
        }

        /// <summary>
        /// Open a transaction object.
        /// </summary>
        /// <param name="path">The path to the object</param>
        /// <returns>The opened object</returns>
        public static NtRegistryTransaction Open(string path)
        {
            return Open(path, null, RegistryTransactionAccessRights.MaximumAllowed);
        }

        /// <summary>
        /// Commit the transaction
        /// </summary>
        public void Commit()
        {
            NtSystemCalls.NtCommitRegistryTransaction(Handle, 0).ToNtException();
        }

        /// <summary>
        /// Rollback the transaction
        /// </summary>
        public void Rollback()
        {
            NtSystemCalls.NtRollbackRegistryTransaction(Handle, 0).ToNtException();
        }
    }

}
