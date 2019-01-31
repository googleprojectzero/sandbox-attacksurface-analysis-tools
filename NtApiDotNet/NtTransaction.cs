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
using System.Text;

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

    [Flags]
    public enum TransactionIsolationFlags
    {
        None = 0,
    }

    public enum TransactionInformationClass
    {
        TransactionBasicInformation,
        TransactionPropertiesInformation,
        TransactionEnlistmentInformation,
        TransactionSuperiorEnlistmentInformation
    }

    public static partial class NtSystemCalls
    {
        [DllImport("ntdll.dll")]
        public static extern NtStatus NtCreateTransaction(out SafeKernelObjectHandle TransactionHandle,
                TransactionAccessRights DesiredAccess, ObjectAttributes ObjectAttributes,
                OptionalGuid Uow, SafeKernelObjectHandle TmHandle,
                TransactionCreateFlags CreateOptions,
                int IsolationLevel,
                TransactionIsolationFlags IsolationFlags,
                LargeInteger Timeout,
                UnicodeString Description);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtOpenTransaction(out SafeKernelObjectHandle TransactionHandle, TransactionAccessRights DesiredAccess,
            ObjectAttributes ObjectAttributes, OptionalGuid Uow, SafeKernelObjectHandle TmHandle);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtCommitTransaction(SafeKernelObjectHandle TransactionHandle, bool Wait);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtRollbackTransaction(SafeKernelObjectHandle TransactionHandle, bool Wait);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtQueryInformationTransaction(
            SafeKernelObjectHandle TransactionHandle,
            TransactionInformationClass TransactionInformationClass,
            SafeBuffer TransactionInformation,
            int TransactionInformationLength,
            out int ReturnLength
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtSetInformationTransaction(
            SafeKernelObjectHandle TransactionHandle,
            TransactionInformationClass TransactionInformationClass,
            SafeBuffer TransactionInformation,
            int TransactionInformationLength
        );
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

    public enum TransactionState
    {
        None = 0,
        Normal,
        Indoubt,
        CommittedNotify
    }

    public enum TransactionOutcome
    {
        None = 0,
        Undetermined,
        Committed,
        Aborted
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct TransactionBasicInformation
    {
        public Guid TransactionId;
        public TransactionState State;
        public TransactionOutcome Outcome;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode), DataStart("Description")]
    public struct TransactionPropertiesInformation
    {
        public int IsolationLevel;
        public int IsolationFlags;
        public LargeIntegerStruct Timeout;
        public TransactionOutcome Outcome;
        public int DescriptionLength;
        public char Description;
    }

#pragma warning restore 1591

    /// <summary>
    /// Interface to abstract the kernel transaction manager support.
    /// </summary>
    public interface INtTransaction
    {
        /// <summary>
        /// Get handle for the transaction.
        /// </summary>
        SafeKernelObjectHandle Handle { get; }

        /// <summary>
        /// Commit the transaction
        /// </summary>
        void Commit();

        /// <summary>
        /// Rollback the transaction
        /// </summary>
        void Rollback();

        /// <summary>
        /// Enable the transaction for anything in the current thread context.
        /// </summary>
        /// <returns>The transaction context. This should be disposed to disable the transaction.</returns>
        TransactionContext Enable();
    }

    /// <summary>
    /// Class to represent a kernel transaction.
    /// </summary>
    [NtType("TmTx")]
    public class NtTransaction : NtObjectWithDuplicateAndInfo<NtTransaction, TransactionAccessRights, TransactionInformationClass>, INtTransaction
    {
        #region Constructors
        internal NtTransaction(SafeKernelObjectHandle handle) : base(handle)
        {
        }
        #endregion

        #region Static Methods
        /// <summary>
        /// Create a transaction
        /// </summary>
        /// <param name="object_attributes">The object attributes</param>
        /// <param name="desired_access">Desired access for the handle</param>
        /// <param name="throw_on_error">True to throw an exception on error.</param>
        /// <param name="create_options">Transaction creation options.</param>
        /// <param name="description">Optional description of the transaction.</param>
        /// <param name="isolation_flags">Isolation flags.</param>
        /// <param name="isolation_level">Isolation level.</param>
        /// <param name="timeout">Optional transaction timeout.</param>
        /// <param name="transaction_manager">Optional transaction manager.</param>
        /// <param name="uow">Optional UOW.</param>
        /// <returns>The NT status code and object result.</returns>
        public static NtResult<NtTransaction> Create(ObjectAttributes object_attributes,
            TransactionAccessRights desired_access,
            Guid? uow, NtTransactionManager transaction_manager,
            TransactionCreateFlags create_options,
            int isolation_level,
            TransactionIsolationFlags isolation_flags,
            NtWaitTimeout timeout,
            string description,
            bool throw_on_error)
        {
            return NtSystemCalls.NtCreateTransaction(out SafeKernelObjectHandle handle,
                desired_access, object_attributes, uow.ToOptional(),
                transaction_manager.GetHandle(), create_options,
                isolation_level, isolation_flags, timeout.ToLargeInteger(), description.ToUnicodeString())
                .CreateResult(throw_on_error, () => new NtTransaction(handle));
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
            return Create(object_attributes, desired_access, null, null, TransactionCreateFlags.None, 0, 0, null, "Flubber", throw_on_error);
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
        /// <param name="desired_access">Desired access for the handle</param>
        /// <param name="create_options">Transaction creation options.</param>
        /// <param name="description">Optional description of the transaction.</param>
        /// <param name="isolation_flags">Isolation flags.</param>
        /// <param name="isolation_level">Isolation level.</param>
        /// <param name="timeout">Optional transaction timeout.</param>
        /// <param name="transaction_manager">Optional transaction manager.</param>
        /// <param name="uow">Optional UOW.</param>
        /// <param name="throw_on_error">True to throw an exception on error.</param>
        /// <returns>The opened transaction</returns>
        public static NtResult<NtTransaction> Create(string path, NtObject root,
            TransactionAccessRights desired_access,
            Guid? uow, NtTransactionManager transaction_manager,
            TransactionCreateFlags create_options,
            int isolation_level,
            TransactionIsolationFlags isolation_flags,
            NtWaitTimeout timeout,
            string description,
            bool throw_on_error)
        {
            using (ObjectAttributes obja = new ObjectAttributes(path, AttributeFlags.CaseInsensitive, root))
            {
                return Create(obja, desired_access, uow, transaction_manager,
                    create_options, isolation_level, isolation_flags,
                    timeout, description, throw_on_error);
            }
        }

        /// <summary>
        /// Create a transaction
        /// </summary>
        /// <param name="path">The path of the transaction</param>
        /// <param name="root">The root if path is relative</param>
        /// <param name="desired_access">Desired access for the handle</param>
        /// <param name="create_options">Transaction creation options.</param>
        /// <param name="description">Optional description of the transaction.</param>
        /// <param name="isolation_flags">Isolation flags.</param>
        /// <param name="isolation_level">Isolation level.</param>
        /// <param name="timeout">Optional transaction timeout.</param>
        /// <param name="transaction_manager">Optional transaction manager.</param>
        /// <param name="uow">Optional UOW.</param>
        /// <returns>The opened transaction</returns>
        public static NtTransaction Create(string path, NtObject root,
            TransactionAccessRights desired_access,
            Guid? uow, NtTransactionManager transaction_manager,
            TransactionCreateFlags create_options,
            int isolation_level,
            TransactionIsolationFlags isolation_flags,
            NtWaitTimeout timeout,
            string description)
        {
            return Create(path, root, desired_access, uow, transaction_manager,
                    create_options, isolation_level, isolation_flags,
                    timeout, description, true).Result;
        }

        /// <summary>
        /// Create a transaction
        /// </summary>
        /// <param name="path">The path of the transaction</param>
        /// <param name="root">The root if path is relative</param>
        /// <param name="desired_access">Desired access for the handle</param>
        /// <param name="throw_on_error">True to throw an exception on error.</param>
        /// <returns>The opened transaction</returns>
        public static NtResult<NtTransaction> Create(string path, NtObject root, TransactionAccessRights desired_access, bool throw_on_error)
        {
            using (ObjectAttributes obja = new ObjectAttributes(path, AttributeFlags.CaseInsensitive, root))
            {
                return Create(obja, desired_access, throw_on_error);
            }
        }

        /// <summary>
        /// Create a transaction
        /// </summary>
        /// <param name="path">The path of the transaction</param>
        /// <param name="root">The root if path is relative</param>
        /// <param name="desired_access">Desired access for the handle</param>
        /// <returns>The opened transaction</returns>
        public static NtTransaction Create(string path, NtObject root, TransactionAccessRights desired_access)
        {
            return Create(path, root, desired_access, true).Result;
        }

        /// <summary>
        /// Create a transaction
        /// </summary>
        /// <param name="path">The path of the transaction</param>
        /// <param name="root">The root if path is relative</param>
        /// <returns>The opened transaction</returns>
        public static NtTransaction Create(string path, NtObject root)
        {
            return Create(path, root, TransactionAccessRights.MaximumAllowed);
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

        /// <summary>
        /// Open a transaction object.
        /// </summary>
        /// <param name="path">The path to the object</param>
        /// <returns>The opened object</returns>
        public static NtTransaction Open(string path)
        {
            return Open(path, null, TransactionAccessRights.MaximumAllowed);
        }

        internal static NtResult<NtObject> FromName(ObjectAttributes object_attributes, AccessMask desired_access, bool throw_on_error)
        {
            return Open(object_attributes, desired_access.ToSpecificAccess<TransactionAccessRights>(), throw_on_error).Cast<NtObject>();
        }
        #endregion

        #region Static Properties
        /// <summary>
        /// Get the current thread's transaction.
        /// </summary>
        public static NtTransaction Current
        {
            get
            {
                IntPtr current = NtRtl.RtlGetCurrentTransaction();
                if (current == IntPtr.Zero)
                    return null;
                return new NtTransaction(new SafeKernelObjectHandle(current, false));
            }
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Commit the transaction
        /// </summary>
        /// <param name="wait">Wait for transaction to commit.</param>
        /// <param name="throw_on_error">True to throw an exception on error.</param>
        /// <returns>The NT status code.</returns>
        public NtStatus Commit(bool wait, bool throw_on_error)
        {
            return NtSystemCalls.NtCommitTransaction(Handle, wait).ToNtException(throw_on_error);
        }

        /// <summary>
        /// Commit the transaction
        /// </summary>
        /// <param name="wait">Wait for transaction to commit.</param>
        public void Commit(bool wait)
        {
            Commit(wait, true);
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
        /// <param name="throw_on_error">True to throw an exception on error.</param>
        /// <returns>The NT status code.</returns>
        public NtStatus Rollback(bool wait, bool throw_on_error)
        {
            return NtSystemCalls.NtRollbackTransaction(Handle, wait).ToNtException(throw_on_error);
        }

        /// <summary>
        /// Rollback the transaction
        /// </summary>
        /// <param name="wait">Wait for transaction to rollback.</param>
        public void Rollback(bool wait)
        {
            Rollback(wait, true);
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

        /// <summary>
        /// Method to query information for this object type.
        /// </summary>
        /// <param name="info_class">The information class.</param>
        /// <param name="buffer">The buffer to return data in.</param>
        /// <param name="return_length">Return length from the query.</param>
        /// <returns>The NT status code for the query.</returns>
        public override NtStatus QueryInformation(TransactionInformationClass info_class, SafeBuffer buffer, out int return_length)
        {
            return NtSystemCalls.NtQueryInformationTransaction(Handle, info_class, buffer, (int)buffer.ByteLength, out return_length);
        }

        /// <summary>
        /// Method to set information for this object type.
        /// </summary>
        /// <param name="info_class">The information class.</param>
        /// <param name="buffer">The buffer to return data in.</param>
        /// <returns>The NT status code for the query.</returns>
        public override NtStatus SetInformation(TransactionInformationClass info_class, SafeBuffer buffer)
        {
            return NtSystemCalls.NtSetInformationTransaction(Handle, info_class, buffer, (int)buffer.ByteLength);
        }

        #endregion

        #region Public Properties
        /// <summary>
        /// Get the ID of the transaction.
        /// </summary>
        public Guid TransactionId => QueryBasicInformation().TransactionId;

        /// <summary>
        /// Get the state of the transaction.
        /// </summary>
        public TransactionState State => QueryBasicInformation().State;

        /// <summary>
        /// Get the outcome of the transaction.
        /// </summary>
        public TransactionOutcome Outcome => QueryBasicInformation().Outcome;

        /// <summary>
        /// Get or set the transaction description.
        /// </summary>
        public string Description
        {
            get => GetDescription(true).Result;
            set => SetDescription(value);
        }

        /// <summary>
        /// Get or set the transaction isolation level.
        /// </summary>
        public int IsolationLevel
        {
            get => GetProperties().IsolationLevel;
            set => SetProperties(value, null, null);
        }

        /// <summary>
        /// Get or set the transaction isolation flags.
        /// </summary>
        public int IsolationFlags
        {
            get => GetProperties().IsolationFlags;
            set => SetProperties(null, value, null);
        }

        /// <summary>
        /// Get or set transaction timeout.
        /// </summary>
        public NtWaitTimeout Timeout
        {
            get => new NtWaitTimeout(GetProperties().Timeout.QuadPart);
            set => SetProperties(null, null, value);
        }

        #endregion

        #region Private Members
        private TransactionBasicInformation QueryBasicInformation()
        {
            return Query<TransactionBasicInformation>(TransactionInformationClass.TransactionBasicInformation);
        }

        private NtResult<SafeStructureInOutBuffer<TransactionPropertiesInformation>> GetPropertiesBuffer(bool throw_on_error)
        {
            return QueryBuffer(TransactionInformationClass.TransactionPropertiesInformation,
                    new TransactionPropertiesInformation(), throw_on_error);
        }

        private NtResult<string> GetDescription(bool throw_on_error)
        {
            using (var buffer = GetPropertiesBuffer(throw_on_error))
            {
                return buffer.Map(b => b.Data.ReadUnicodeString(b.Result.DescriptionLength / 2));
            }
        }

        private TransactionPropertiesInformation GetProperties()
        {
            using (var buffer = GetPropertiesBuffer(true))
            {
                return buffer.Result.Result;
            }
        }

        // Set description only.
        private void SetDescription(string description)
        {
            byte[] str = Encoding.Unicode.GetBytes(description);
            TransactionPropertiesInformation init_value = GetProperties();
            init_value.DescriptionLength = str.Length;
            using (var buffer = new SafeStructureInOutBuffer<TransactionPropertiesInformation>(init_value, str.Length, true))
            {
                buffer.Data.WriteBytes(str);
                SetInformation(TransactionInformationClass.TransactionPropertiesInformation, buffer).ToNtException();
            }
        }

        // Set properties exception description.
        private void SetProperties(int? isolation_level, int? isolation_flags, NtWaitTimeout timeout)
        {
            using (var buffer = GetPropertiesBuffer(true).Result)
            {
                TransactionPropertiesInformation init_value = buffer.Result;
                if (isolation_level.HasValue)
                {
                    init_value.IsolationLevel = isolation_level.Value;
                }
                if (isolation_flags.HasValue)
                {
                    init_value.IsolationFlags = isolation_flags.Value;
                }
                if (timeout != null)
                {
                    init_value.Timeout = new LargeIntegerStruct() { QuadPart = timeout.Timeout };
                }

                buffer.Write(0, init_value);
                SetInformation(TransactionInformationClass.TransactionPropertiesInformation, buffer).ToNtException();
            }
        }

        #endregion
    }
}
