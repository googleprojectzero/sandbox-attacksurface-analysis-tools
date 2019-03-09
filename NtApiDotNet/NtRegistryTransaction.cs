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

namespace NtApiDotNet
{
    /// <summary>
    /// Class to represent a registry transaction object
    /// </summary>
    [NtType("RegistryTransaction")]
    public sealed class NtRegistryTransaction : NtObjectWithDuplicate<NtRegistryTransaction, RegistryTransactionAccessRights>, INtTransaction
    {
        #region Constructors
        internal NtRegistryTransaction(SafeKernelObjectHandle handle) : base(handle)
        {
        }

        internal sealed class NtTypeFactoryImpl : NtTypeFactoryImplBase
        {
            public NtTypeFactoryImpl() : base(true)
            {
            }

            protected override sealed NtResult<NtRegistryTransaction> OpenInternal(ObjectAttributes obj_attributes,
                RegistryTransactionAccessRights desired_access, bool throw_on_error)
            {
                return NtRegistryTransaction.Open(obj_attributes, desired_access, throw_on_error);
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
        /// <returns>The NT status code and object result.</returns>
        public static NtResult<NtRegistryTransaction> Create(ObjectAttributes object_attributes, RegistryTransactionAccessRights desired_access, bool throw_on_error)
        {
            return NtSystemCalls.NtCreateRegistryTransaction(out SafeKernelObjectHandle handle,
                desired_access, object_attributes, 0).CreateResult(throw_on_error, () => new NtRegistryTransaction(handle));
        }

        /// <summary>
        /// Create a transaction
        /// </summary>
        /// <param name="object_attributes">The object attributes</param>
        /// <param name="desired_access">Desired access for the handle</param>
        /// <returns>The opened transaction</returns>
        public static NtRegistryTransaction Create(ObjectAttributes object_attributes, RegistryTransactionAccessRights desired_access)
        {
            return Create(object_attributes, desired_access, true).Result;
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
        /// <param name="throw_on_error">True to throw an exception on error.</param>
        /// <returns>The NT status code and object result.</returns>
        public static NtResult<NtRegistryTransaction> Open(ObjectAttributes object_attributes, RegistryTransactionAccessRights desired_access, bool throw_on_error)
        {
            return NtSystemCalls.NtOpenRegistryTransaction(out SafeKernelObjectHandle handle,
                desired_access, object_attributes).CreateResult(throw_on_error, () => new NtRegistryTransaction(handle));
        }

        /// <summary>
        /// Open a transaction object.
        /// </summary>
        /// <param name="object_attributes">The object attributes for the object</param>
        /// <param name="desired_access">The desired access for the object</param>
        /// <returns>The opened object</returns>
        public static NtRegistryTransaction Open(ObjectAttributes object_attributes, RegistryTransactionAccessRights desired_access)
        {
            return Open(object_attributes, desired_access, true).Result;
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

        #endregion

        #region Public Methods

        /// <summary>
        /// Commit the transaction
        /// </summary>
        public void Commit()
        {
            NtSystemCalls.NtCommitRegistryTransaction(Handle, true).ToNtException();
        }

        /// <summary>
        /// Rollback the transaction
        /// </summary>
        public void Rollback()
        {
            NtSystemCalls.NtRollbackRegistryTransaction(Handle, true).ToNtException();
        }

        /// <summary>
        /// Enable the transaction for anything in the current thread context.
        /// </summary>
        /// <returns>The transaction context. This should be disposed to disable the transaction.</returns>
        public TransactionContext Enable()
        {
            return new TransactionContext(Handle);
        }

        #endregion
    }
}
