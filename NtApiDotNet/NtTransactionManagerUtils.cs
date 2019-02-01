//  Copyright 2019 Google Inc. All Rights Reserved.
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
#pragma warning disable 1591
    public enum KtmObjectType
    {
        Transaction,
        TransactionManager,
        ResourceManager,
        Enlistment,
        Invalid
    }

    [StructLayout(LayoutKind.Sequential), DataStart("ObjectIds")]
    public struct KtmObjectCursor
    {
        public Guid LastQuery;
        public int ObjectIdCount;
        public Guid ObjectIds;
    }

    public static partial class NtSystemCalls
    {
        [DllImport("ntdll.dll")]
        public static extern NtStatus NtEnumerateTransactionObject(
          SafeKernelObjectHandle RootObjectHandle,
          KtmObjectType QueryType,
          ref KtmObjectCursor ObjectCursor,
          int ObjectCursorLength,
          out int ReturnLength
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtFreezeTransactions(
            LargeInteger FreezeTimeout,
            LargeInteger ThawTimeout
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtThawTransactions();
    }

#pragma warning restore 1591

    /// <summary>
    /// General utilities for the kernel transaction manager.
    /// </summary>
    public static class NtTransactionManagerUtils
    {
        #region Static Methods

        /// <summary>
        /// Enumerate transaction objects of a specific type from a root handle.
        /// </summary>
        /// <param name="root_object_handle">The root handle to enumearate from.</param>
        /// <param name="query_type">The type of object to query.</param>
        /// <returns>The list of enumerated transaction object GUIDs.</returns>
        public static IEnumerable<Guid> EnumerateTransactionObjects(SafeKernelObjectHandle root_object_handle, KtmObjectType query_type)
        {
            List<Guid> ret = new List<Guid>();
            KtmObjectCursor cursor = new KtmObjectCursor();
            int size = Marshal.SizeOf(cursor);
            NtStatus status = NtSystemCalls.NtEnumerateTransactionObject(root_object_handle, query_type, ref cursor, size, out int return_length);
            while (status == NtStatus.STATUS_SUCCESS)
            {
                ret.Add(cursor.ObjectIds);
                status = NtSystemCalls.NtEnumerateTransactionObject(root_object_handle, query_type, ref cursor, size, out return_length);
            }
            return ret.AsReadOnly();
        }

        /// <summary>
        /// Enumerate all transaction objects of a specific type.
        /// </summary>
        /// <param name="query_type">The type of object to query.</param>
        /// <returns>The list of enumerated transaction object GUIDs.</returns>
        public static IEnumerable<Guid> EnumerateTransactionObjects(KtmObjectType query_type)
        {
            return EnumerateTransactionObjects(SafeKernelObjectHandle.Null, query_type);
        }

        /// <summary>
        /// Freeze all transactions. Needs SeRestorePrivilege.
        /// </summary>
        /// <param name="freeze_timeout">The freeze wait timeout.</param>
        /// <param name="thaw_timeout">The thaw wait timeout.</param>
        /// <param name="throw_on_error">Throw exception on error.</param>
        /// <returns>The NT status code.</returns>
        public static NtStatus FreezeTransactions(NtWaitTimeout freeze_timeout, NtWaitTimeout thaw_timeout, bool throw_on_error)
        {
            return NtSystemCalls.NtFreezeTransactions(freeze_timeout.ToLargeInteger(), thaw_timeout.ToLargeInteger()).ToNtException(throw_on_error);
        }

        /// <summary>
        /// Freeze all transactions. Needs SeRestorePrivilege.
        /// </summary>
        /// <param name="freeze_timeout">The freeze wait timeout.</param>
        /// <param name="thaw_timeout">The thaw wait timeout.</param>
        public static void FreezeTransactions(NtWaitTimeout freeze_timeout, NtWaitTimeout thaw_timeout)
        {
            FreezeTransactions(freeze_timeout, thaw_timeout, true);
        }

        /// <summary>
        /// Thaw transactions. Needs SeRestorePrivilege.
        /// </summary>
        /// <param name="throw_on_error">Throw exception on error.</param>
        /// <returns>The NT status code.</returns>
        public static NtStatus ThawTransactions(bool throw_on_error)
        {
            return NtSystemCalls.NtThawTransactions().ToNtException(throw_on_error);
        }

        /// <summary>
        /// Thaw transactions. Needs SeRestorePrivilege.
        /// </summary>
        /// <returns>The NT status code.</returns>
        public static void ThawTransactions()
        {
            ThawTransactions(true);
        }

        #endregion

        #region Internal Static Methods

        internal static IEnumerable<T> GetAccessibleTransactionObjects<T>(
            SafeKernelObjectHandle handle,
            KtmObjectType object_type,
            Func<Guid, NtResult<T>> open_func)
        {
            return EnumerateTransactionObjects(handle, object_type)
                .Select(open_func)
                .Where(r => r.IsSuccess)
                .Select(r => r.Result)
                .ToList().AsReadOnly();
        }

        #endregion
    }
}
