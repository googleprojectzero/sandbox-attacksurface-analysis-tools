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
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace NtApiDotNet
{
    /// <summary>
    /// Class to represent a kernel transaction.
    /// </summary>
    [NtType("TmTx")]
    public class NtTransaction : NtObjectWithDuplicateAndInfo<NtTransaction, TransactionAccessRights, TransactionInformationClass, TransactionInformationClass>, INtTransaction
    {
        #region Constructors
        internal NtTransaction(SafeKernelObjectHandle handle) : base(handle)
        {
        }

        internal sealed class NtTypeFactoryImpl : NtTypeFactoryImplBase
        {
            public NtTypeFactoryImpl() : base(false)
            {
            }
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
        /// <param name="create_options">Transaction creation options.</param>
        /// <param name="description">Optional description of the transaction.</param>
        /// <param name="isolation_flags">Isolation flags.</param>
        /// <param name="isolation_level">Isolation level.</param>
        /// <param name="timeout">Optional transaction timeout.</param>
        /// <param name="transaction_manager">Optional transaction manager.</param>
        /// <param name="uow">Optional UOW.</param>
        /// <returns>The NT status code and object result.</returns>
        public static NtTransaction Create(ObjectAttributes object_attributes,
            TransactionAccessRights desired_access,
            Guid? uow, NtTransactionManager transaction_manager,
            TransactionCreateFlags create_options,
            int isolation_level,
            TransactionIsolationFlags isolation_flags,
            NtWaitTimeout timeout,
            string description)
        {
            return Create(object_attributes, desired_access, uow,
                transaction_manager, create_options,
                isolation_level, isolation_flags, timeout, description, true).Result;
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
            return Create(object_attributes, desired_access, null, null, TransactionCreateFlags.None, 0, 0, null, null, throw_on_error);
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
        /// <param name="object_attributes">The object attributes for the object</param>
        /// <param name="desired_access">The desired access for the object</param>
        /// <param name="transaction_manager">Optional transaction manager.</param>
        /// <param name="uow">UOW Guid.</param>
        /// <param name="throw_on_error">True to throw an exception on error.</param>
        /// <returns>The NT status code and object result.</returns>
        public static NtResult<NtTransaction> Open(ObjectAttributes object_attributes, TransactionAccessRights desired_access, 
            Guid uow, NtTransactionManager transaction_manager, bool throw_on_error)
        {
            return NtSystemCalls.NtOpenTransaction(out SafeKernelObjectHandle handle, desired_access, object_attributes,
                ref uow, transaction_manager.GetHandle()).CreateResult(throw_on_error, () => new NtTransaction(handle));
        }

        /// <summary>
        /// Open a transaction object.
        /// </summary>
        /// <param name="object_attributes">The object attributes for the object</param>
        /// <param name="desired_access">The desired access for the object</param>
        /// <param name="transaction_manager">Optional transaction manager.</param>
        /// <param name="uow">UOW Guid.</param>
        /// <returns>The object result.</returns>
        public static NtTransaction Open(ObjectAttributes object_attributes, TransactionAccessRights desired_access,
            Guid uow, NtTransactionManager transaction_manager)
        {
            return Open(object_attributes, desired_access, uow, transaction_manager, true).Result;
        }

        /// <summary>
        /// Open a transaction object.
        /// </summary>
        /// <param name="desired_access">The desired access for the object</param>
        /// <param name="transaction_manager">Optional transaction manager.</param>
        /// <param name="uow">UOW Guid.</param>
        /// <returns>The object result.</returns>
        public static NtTransaction Open(TransactionAccessRights desired_access,
            Guid uow, NtTransactionManager transaction_manager)
        {
            return Open(null, desired_access, uow, transaction_manager);
        }

        /// <summary>
        /// Open a transaction object.
        /// </summary>
        /// <param name="transaction_manager">Optional transaction manager.</param>
        /// <param name="uow">UOW Guid.</param>
        /// <returns>The object result.</returns>
        public static NtTransaction Open(Guid uow, NtTransactionManager transaction_manager)
        {
            return Open(TransactionAccessRights.MaximumAllowed, uow, transaction_manager);
        }

        /// <summary>
        /// Open a transaction object.
        /// </summary>
        /// <param name="uow">UOW Guid.</param>
        /// <returns>The object result.</returns>
        public static NtTransaction Open(Guid uow)
        {
            return Open(uow, null);
        }

        /// <summary>
        /// Get a list of all accessible transaction objects.
        /// </summary>
        /// <param name="object_attributes">The object attributes for the object</param>
        /// <param name="transaction_manager">Optional transaction manager.</param>
        /// <param name="desired_access">The access for the transaction objects.</param>
        /// <returns>The list of all accessible transaction objects.</returns>
        public static IEnumerable<NtTransaction> GetAccessibleTransaction(ObjectAttributes object_attributes, 
            TransactionAccessRights desired_access, NtTransactionManager transaction_manager)
        {
            return NtTransactionManagerUtils.GetAccessibleTransactionObjects(
                transaction_manager.GetHandle(), KtmObjectType.Transaction,
                id => Open(object_attributes, desired_access, id, transaction_manager, false));
        }

        /// <summary>
        /// Get a list of all accessible transaction objects.
        /// </summary>
        /// <param name="desired_access">The access for the transaction objects.</param>
        /// <returns>The list of all accessible transaction objects.</returns>
        public static IEnumerable<NtTransaction> GetAccessibleTransaction(TransactionAccessRights desired_access)
        {
            return GetAccessibleTransaction(null, desired_access, null);
        }

        /// <summary>
        /// Get a list of all accessible transaction objects.
        /// </summary>
        /// <returns>The list of all accessible transaction objects.</returns>
        public static IEnumerable<NtTransaction> GetAccessibleTransaction()
        {
            return GetAccessibleTransaction(TransactionAccessRights.MaximumAllowed);
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
            return NtSystemCalls.NtQueryInformationTransaction(Handle, info_class, buffer, buffer.GetLength(), out return_length);
        }

        /// <summary>
        /// Method to set information for this object type.
        /// </summary>
        /// <param name="info_class">The information class.</param>
        /// <param name="buffer">The buffer to set data from.</param>
        /// <returns>The NT status code for the set.</returns>
        public override NtStatus SetInformation(TransactionInformationClass info_class, SafeBuffer buffer)
        {
            return NtSystemCalls.NtSetInformationTransaction(Handle, info_class, buffer, buffer.GetLength());
        }

        #endregion

        #region Public Properties
        /// <summary>
        /// Get the ID of the transaction.
        /// </summary>
        public Guid TransactionId => QueryBasicInformation().TransactionId;

        /// <summary>
        /// Get the Unit of Work ID of the transaction. Same as transaction ID.
        /// </summary>
        public Guid UnitOfWork => TransactionId;

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

        /// <summary>
        /// Query list of enlistments for this transaction.
        /// </summary>
        public IEnumerable<TransactionEnlistmentPair> Enlistments
        {
            get
            {
                using (var buffer = QueryBuffer<TransactionEnlistmentsInformation>(TransactionInformationClass.TransactionEnlistmentInformation))
                {
                    int count = buffer.Result.NumberOfEnlistments;
                    TransactionEnlistmentPair[] pairs = new TransactionEnlistmentPair[count];
                    buffer.Data.ReadArray(0, pairs, 0, count);
                    return pairs;
                }
            }
        }

        /// <summary>
        /// Query the superior enlistment for this transaction.
        /// </summary>
        public TransactionEnlistmentPair SuperiorEnlistment => Query<TransactionSuperiorEnlistmentInformation>(
            TransactionInformationClass.TransactionSuperiorEnlistmentInformation).SuperiorEnlistmentPair;

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
                SetBuffer(TransactionInformationClass.TransactionPropertiesInformation, buffer);
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
                    init_value.Timeout = new LargeIntegerStruct() { QuadPart = timeout.Timeout.QuadPart };
                }

                buffer.Write(0, init_value);
                SetBuffer(TransactionInformationClass.TransactionPropertiesInformation, buffer);
            }
        }

        #endregion
    }
}
