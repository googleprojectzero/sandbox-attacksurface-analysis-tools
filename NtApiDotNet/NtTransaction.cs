//  Copyright 2018 Google Inc. All Rights Reserved.
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
    public enum TransactionAccessRights : uint
    {
        QueryInformation = 1,
        SetInformation = 2,
        Enlist = 4,
        Commit = 8,
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

    [Flags]
    public enum TransactionCreateFlags
    {
        None = 0,
        DoNotPromote = 1,
    }

    public static partial class NtSystemCalls
    {
        [DllImport("ntdll.dll")]
        public static extern NtStatus NtCreateTransaction(out SafeKernelObjectHandle TransactionHandle, 
                TransactionAccessRights DesiredAccess, ObjectAttributes ObjectAttributes, 
                OptionalGuid Uow, SafeKernelObjectHandle TmHandle,
                TransactionCreateFlags CreateOptions,
                int IsolationLevel,
                int IsolationFlags,
                LargeInteger Timeout,
                UnicodeString Description);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtOpenTransaction(out SafeKernelObjectHandle TransactionHandle, TransactionAccessRights DesiredAccess,
            ObjectAttributes ObjectAttributes, OptionalGuid Uow, SafeKernelObjectHandle TmHandle);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtCommitTransaction(SafeKernelObjectHandle TransactionHandle, bool Wait);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtRollbackTransaction(SafeKernelObjectHandle TransactionHandle, bool Wait);
    }

    public static partial class NtRtl
    {
        [DllImport("ntdll.dll")]
        public static extern bool RtlSetCurrentTransaction(SafeKernelObjectHandle TransactionHandle);

        [DllImport("ntdll.dll")]
        public static extern IntPtr RtlGetCurrentTransaction();
    }

    public sealed class TransactionContext : IDisposable
    {
        internal TransactionContext(SafeKernelObjectHandle transaction)
        {
            NtRtl.RtlSetCurrentTransaction(transaction);
        }

        void IDisposable.Dispose()
        {
            NtRtl.RtlSetCurrentTransaction(SafeKernelObjectHandle.Null);
        }
    }

#pragma warning restore 1591

    /// <summary>
    /// Class to represent a kernel transaction.
    /// </summary>
    [NtType("TmTx")]
    public class NtTransaction : NtObjectWithDuplicate<NtTransaction, TransactionAccessRights>
    {
        internal NtTransaction(SafeKernelObjectHandle handle) : base(handle)
        {
        }

        /// <summary>
        /// Create a transaction
        /// </summary>
        /// <param name="object_attributes">The object attributes</param>
        /// <param name="desired_access">Desired access for the handle</param>
        /// <param name="throw_on_error">True to throw an exception on error.</param>
        /// <returns>The NT status code and object result.</returns>
        public static NtResult<NtTransaction> Create(ObjectAttributes object_attributes, TransactionAccessRights desired_access, bool throw_on_error)
        {
            return NtSystemCalls.NtCreateTransaction(out SafeKernelObjectHandle handle,
                desired_access, object_attributes, null,
                SafeKernelObjectHandle.Null, TransactionCreateFlags.None,
                0, 0, null, null).CreateResult(throw_on_error, () => new NtTransaction(handle));
        }

        /// <summary>
        /// Create a transaction
        /// </summary>
        /// <param name="object_attributes">The object attributes</param>
        /// <param name="desired_access">Desired access for the handle</param>
        /// <returns>The opened transaction</returns>
        public static NtTransaction Create(ObjectAttributes object_attributes, TransactionAccessRights desired_access)
        {
            return Create(object_attributes, desired_access, true).Result;
        }

        /// <summary>
        /// Create a transaction
        /// </summary>
        /// <param name="path">The path of the transaction</param>
        /// <param name="root">The root if path is relative</param>
        /// <returns>The opened transaction</returns>
        public static NtTransaction Create(string path, NtObject root)
        {
            using (ObjectAttributes obja = new ObjectAttributes(path, AttributeFlags.CaseInsensitive, root))
            {
                return Create(obja, TransactionAccessRights.MaximumAllowed);
            }
        }

        /// <summary>
        /// Create a transaction
        /// </summary>
        /// <param name="path">The path of the transaction</param>
        /// <returns>The opened transaction</returns>
        public static NtTransaction Create(string path)
        {
            return Create(path, null);
        }

        /// <summary>
        /// Create a transaction
        /// </summary>
        /// <returns>The opened transaction</returns>
        public static NtTransaction Create()
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
        public static NtTransaction Open(string path, NtObject root, TransactionAccessRights desired_access)
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
        /// <param name="throw_on_error">True to throw an exception on error.</param>
        /// <returns>The NT status code and object result.</returns>
        public static NtResult<NtTransaction> Open(ObjectAttributes object_attributes, TransactionAccessRights desired_access, bool throw_on_error)
        {
            return NtSystemCalls.NtOpenTransaction(out SafeKernelObjectHandle handle, desired_access, object_attributes, 
                null, SafeKernelObjectHandle.Null).CreateResult(throw_on_error, () => new NtTransaction(handle));
        }

        /// <summary>
        /// Open a transaction object.
        /// </summary>
        /// <param name="object_attributes">The object attributes for the object</param>
        /// <param name="desired_access">The desired access for the object</param>
        /// <returns>The opened object</returns>
        public static NtTransaction Open(ObjectAttributes object_attributes, TransactionAccessRights desired_access)
        {
            return Open(object_attributes, desired_access, true).Result;
        }

        internal static NtResult<NtObject> FromName(ObjectAttributes object_attributes, AccessMask desired_access, bool throw_on_error)
        {
            return Open(object_attributes, desired_access.ToSpecificAccess<TransactionAccessRights>(), throw_on_error).Cast<NtObject>();
        }

        /// <summary>
        /// Open a transaction object.
        /// </summary>
        /// <param name="path">The path to the object</param>
        /// <returns>The opened object</returns>
        public static NtTransaction Open(string path)
        {
            return Open(path, null, TransactionAccessRights.MaximumAllowed);
        }

        /// <summary>
        /// Commit the transaction
        /// </summary>
        /// <param name="wait">Wait for transaction to commit.</param>
        public void Commit(bool wait)
        {
            NtSystemCalls.NtCommitTransaction(Handle, wait).ToNtException();
        }

        /// <summary>
        /// Commit the transaction
        /// </summary>
        public void Commit()
        {
            Commit(true);
        }

        /// <summary>
        /// Rollback the transaction
        /// </summary>
        /// <param name="wait">Wait for transaction to rollback.</param>
        public void Rollback(bool wait)
        {
            NtSystemCalls.NtRollbackTransaction(Handle, wait).ToNtException();
        }

        /// <summary>
        /// Rollback the transaction
        /// </summary>
        public void Rollback()
        {
            Rollback(true);
        }

        /// <summary>
        /// Enable the transaction for anything in the current thread context.
        /// </summary>
        /// <returns>The transaction context. This should be disposed to disable the transaction.</returns>
        public TransactionContext Enable()
        {
            return new TransactionContext(Handle);
        }
    }
}
