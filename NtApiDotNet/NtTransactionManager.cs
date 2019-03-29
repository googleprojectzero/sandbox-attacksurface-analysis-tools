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
using System.Runtime.InteropServices;

namespace NtApiDotNet
{
    /// <summary>
    /// Class to represent a kernel transaction manager.
    /// </summary>
    [NtType("TmTm")]
    public sealed class NtTransactionManager : NtObjectWithDuplicateAndInfo<NtTransactionManager, TransactionManagerAccessRights, 
        TransactionManagerInformationClass, TransactionManagerInformationClass>
    {
        #region Constructors
        internal NtTransactionManager(SafeKernelObjectHandle handle)
            : base(handle)
        {
        }

        internal sealed class NtTypeFactoryImpl : NtTypeFactoryImplBase
        {
            public NtTypeFactoryImpl() : base(true)
            {
            }

            protected override sealed NtResult<NtTransactionManager> OpenInternal(ObjectAttributes obj_attributes,
                TransactionManagerAccessRights desired_access, bool throw_on_error)
            {
                return NtTransactionManager.Open(obj_attributes, desired_access,
                    null, null, TransactionManagerOpenOptions.None, throw_on_error);
            }
        }

        #endregion

        #region Static Methods
        /// <summary>
        /// Create a new transaction manager object.
        /// </summary>
        /// <param name="object_attributes">The object attributes</param>
        /// <param name="desired_access">Desired access for the handle</param>
        /// <param name="throw_on_error">True to throw an exception on error.</param>
        /// <param name="log_filename">The CLFS log file to create if not volatile.</param>
        /// <param name="create_options">Creation options flags.</param>
        /// <param name="commit_strength">Commit strength, set to 0.</param>
        /// <returns>The NT status code and object result.</returns>
        public static NtResult<NtTransactionManager> Create(ObjectAttributes object_attributes,
                                                            TransactionManagerAccessRights desired_access,
                                                            string log_filename,
                                                            TransactionManagerCreateOptions create_options,
                                                            int commit_strength,
                                                            bool throw_on_error)
        {
            return NtSystemCalls.NtCreateTransactionManager(out SafeKernelObjectHandle handle, desired_access, object_attributes,
                log_filename.ToUnicodeString(),
                create_options, commit_strength).CreateResult(throw_on_error, () => new NtTransactionManager(handle));
        }

        /// <summary>
        /// Create a new transaction manager object.
        /// </summary>
        /// <param name="object_attributes">The object attributes</param>
        /// <param name="desired_access">Desired access for the handle</param>
        /// <param name="log_filename">The CLFS log file to create if not volatile.</param>
        /// <param name="create_options">Creation options flags.</param>
        /// <param name="commit_strength">Commit strength, set to 0.</param>
        /// <returns>The object result.</returns>
        public static NtTransactionManager Create(ObjectAttributes object_attributes,
                                                 TransactionManagerAccessRights desired_access,
                                                 string log_filename,
                                                 TransactionManagerCreateOptions create_options,
                                                 int commit_strength)
        {
            return Create(object_attributes, desired_access, log_filename, create_options, commit_strength, true).Result;
        }

        /// <summary>
        /// Create a new transaction manager object.
        /// </summary>
        /// <param name="path">The path to the transaction manager.</param>
        /// <param name="root">The root if path is relative.</param>
        /// <param name="desired_access">Desired access for the handle</param>
        /// <param name="log_filename">The CLFS log file to create if not volatile.</param>
        /// <param name="create_options">Creation options flags.</param>
        /// <param name="throw_on_error">True to throw an exception on error.</param>
        /// <returns>The object result.</returns>
        public static NtResult<NtTransactionManager> Create(string path, NtObject root,
                                                 TransactionManagerAccessRights desired_access,
                                                 string log_filename,
                                                 TransactionManagerCreateOptions create_options,
                                                 bool throw_on_error)
        {
            using (var obj_attr = new ObjectAttributes(path, AttributeFlags.CaseInsensitive, root))
            {
                return Create(obj_attr, desired_access, log_filename, create_options, 0, throw_on_error);
            }
        }

        /// <summary>
        /// Create a new transaction manager object.
        /// </summary>
        /// <param name="path">The path to the transaction manager.</param>
        /// <param name="root">The root if path is relative.</param>
        /// <param name="desired_access">Desired access for the handle</param>
        /// <param name="log_filename">The CLFS log file to create if not volatile.</param>
        /// <param name="create_options">Creation options flags.</param>
        /// <returns>The object result.</returns>
        public static NtTransactionManager Create(string path, NtObject root,
                                                 TransactionManagerAccessRights desired_access,
                                                 string log_filename,
                                                 TransactionManagerCreateOptions create_options)
        {
            return Create(path, root, desired_access, log_filename, create_options, true).Result;
        }

        /// <summary>
        /// Create a new volatile transaction manager object.
        /// </summary>
        /// <param name="path">The path to the transaction manager.</param>
        /// <param name="root">The root if path is relative.</param>
        /// <param name="desired_access">Desired access for the handle</param>
        /// <returns>The object result.</returns>
        public static NtTransactionManager CreateVolatile(string path, NtObject root,
                                                 TransactionManagerAccessRights desired_access)
        {
            return Create(path, root, desired_access, null, TransactionManagerCreateOptions.Volatile);
        }

        /// <summary>
        /// Create a new volatile transaction manager object.
        /// </summary>
        /// <param name="path">The path to the transaction manager.</param>
        /// <param name="root">The root if path is relative.</param>
        /// <returns>The object result.</returns>
        public static NtTransactionManager CreateVolatile(string path, NtObject root)
        {
            return CreateVolatile(path, root, TransactionManagerAccessRights.MaximumAllowed);
        }

        /// <summary>
        /// Create a new volatile transaction manager object.
        /// </summary>
        /// <param name="path">The path to the transaction manager.</param>
        /// <returns>The object result.</returns>
        public static NtTransactionManager CreateVolatile(string path)
        {
            return CreateVolatile(path, null);
        }

        /// <summary>
        /// Create a new volatile transaction manager object.
        /// </summary>
        /// <returns>The object result.</returns>
        public static NtTransactionManager CreateVolatile()
        {
            return CreateVolatile(null);
        }

        /// <summary>
        /// Open a existing transaction manager object.
        /// </summary>
        /// <param name="object_attributes">The object attributes</param>
        /// <param name="desired_access">Desired access for the handle</param>
        /// <param name="log_filename">The CLFS log file to create if not volatile.</param>
        /// <param name="tm_identity">Identity of the transaction manager.</param>
        /// <param name="open_options">Open options flags.</param>
        /// <param name="throw_on_error">True to throw an exception on error.</param>
        /// <returns>The NT status code and object result.</returns>
        public static NtResult<NtTransactionManager> Open(ObjectAttributes object_attributes,
                                                            TransactionManagerAccessRights desired_access,
                                                            string log_filename,
                                                            Guid? tm_identity,
                                                            TransactionManagerOpenOptions open_options,
                                                            bool throw_on_error)
        {
            return NtSystemCalls.NtOpenTransactionManager(out SafeKernelObjectHandle handle, desired_access, object_attributes,
                log_filename.ToUnicodeString(), tm_identity.ToOptional(),
                open_options).CreateResult(throw_on_error, () => new NtTransactionManager(handle));
        }

        /// <summary>
        /// Open a existing transaction manager object.
        /// </summary>
        /// <param name="object_attributes">The object attributes</param>
        /// <param name="desired_access">Desired access for the handle</param>
        /// <param name="tm_identity">Identity of the transaction manager.</param>
        /// <param name="log_filename">The CLFS log file to create if not volatile.</param>
        /// <param name="open_options">Open options flags.</param>
        /// <returns>The object result.</returns>
        public static NtTransactionManager Open(ObjectAttributes object_attributes,
                                                TransactionManagerAccessRights desired_access,
                                                string log_filename,
                                                Guid? tm_identity,
                                                TransactionManagerOpenOptions open_options)
        {
            return Open(object_attributes, desired_access, log_filename, tm_identity, open_options, true).Result;
        }

        /// <summary>
        /// Open an existing transaction manager object.
        /// </summary>
        /// <param name="path">The path to the transaction manager.</param>
        /// <param name="root">The root if path is relative.</param>
        /// <param name="desired_access">Desired access for the handle</param>
        /// <param name="tm_identity">Identity of the transaction manager.</param>
        /// <param name="log_filename">The CLFS log file to create if not volatile.</param>
        /// <param name="open_options">Open options flags.</param>
        /// <param name="throw_on_error">True to throw an exception on error.</param>
        /// <returns>The object result.</returns>
        public static NtResult<NtTransactionManager> Open(string path, NtObject root,
                                                 TransactionManagerAccessRights desired_access,
                                                 string log_filename,
                                                 Guid? tm_identity,
                                                 TransactionManagerOpenOptions open_options,
                                                 bool throw_on_error)
        {
            using (var obj_attr = new ObjectAttributes(path, AttributeFlags.CaseInsensitive, root))
            {
                return Open(obj_attr, desired_access, log_filename, tm_identity, open_options, throw_on_error);
            }
        }

        /// <summary>
        /// Open an existing transaction manager object.
        /// </summary>
        /// <param name="path">The path to the transaction manager.</param>
        /// <param name="root">The root if path is relative.</param>
        /// <param name="desired_access">Desired access for the handle</param>
        /// <param name="tm_identity">Identity of the transaction manager.</param>
        /// <param name="log_filename">The CLFS log file to create if not volatile.</param>
        /// <param name="open_options">Open options flags.</param>
        /// <returns>The object result.</returns>
        public static NtTransactionManager Open(string path, NtObject root,
                                                 TransactionManagerAccessRights desired_access,
                                                 string log_filename,
                                                  Guid? tm_identity,
                                                 TransactionManagerOpenOptions open_options)
        {
            return Open(path, root, desired_access, log_filename, tm_identity, open_options, true).Result;
        }

        /// <summary>
        /// Open an existing transaction manager object.
        /// </summary>
        /// <param name="path">The path to the transaction manager.</param>
        /// <param name="root">The root if path is relative.</param>
        /// <param name="desired_access">Desired access for the handle</param>
        /// <returns>The object result.</returns>
        public static NtTransactionManager Open(string path, NtObject root,
                                                 TransactionManagerAccessRights desired_access)
        {
            return Open(path, root, desired_access, null, null, TransactionManagerOpenOptions.None);
        }

        /// <summary>
        /// Open an existing transaction manager object.
        /// </summary>
        /// <param name="path">The path to the transaction manager.</param>
        /// <param name="root">The root if path is relative.</param>
        /// <returns>The object result.</returns>
        public static NtTransactionManager Open(string path, NtObject root)
        {
            return Open(path, root, TransactionManagerAccessRights.MaximumAllowed);
        }

        /// <summary>
        /// Open an existing transaction manager object.
        /// </summary>
        /// <param name="path">The path to the transaction manager.</param>
        /// <returns>The object result.</returns>
        public static NtTransactionManager Open(string path)
        {
            return Open(path, null);
        }

        /// <summary>
        /// Rename transaction manager object. The new identity can be queried with the Identity property on the object.
        /// </summary>
        /// <param name="logpath">The path to the transaction log file.</param>
        /// <param name="identity">The existing transaction manager identity.</param>
        /// <param name="throw_on_error">True to throw an exception on error.</param>
        /// <returns>The NT status code</returns>
        public static NtStatus Rename(string logpath, Guid identity, bool throw_on_error)
        {
            return NtSystemCalls.NtRenameTransactionManager(logpath.ToUnicodeString(),
                new OptionalGuid(identity)).ToNtException(throw_on_error);
        }

        /// <summary>
        /// Get a list of all accessible transaction manager objects.
        /// </summary>
        /// <param name="object_attributes">Object attributes for opened handle.</param>
        /// <param name="desired_access">The access for the transaction manager objects.</param>
        /// <param name="options">Open options.</param>
        /// <returns>The list of all accessible transaction manager objects.</returns>
        public static IEnumerable<NtTransactionManager> GetAccessibleTransactionManager(ObjectAttributes object_attributes, 
            TransactionManagerAccessRights desired_access, TransactionManagerOpenOptions options)
        {
            return NtTransactionManagerUtils.GetAccessibleTransactionObjects(
                SafeKernelObjectHandle.Null, KtmObjectType.TransactionManager,
                id => Open(object_attributes, desired_access, null, id, options, false));
        }

        /// <summary>
        /// Get a list of all accessible transaction manager objects.
        /// </summary>
        /// <param name="desired_access">The access for the transaction manager objects.</param>
        /// <returns>The list of all accessible transaction manager objects.</returns>
        public static IEnumerable<NtTransactionManager> GetAccessibleTransactionManager(TransactionManagerAccessRights desired_access)
        {
            return GetAccessibleTransactionManager(null, desired_access, TransactionManagerOpenOptions.None);
        }

        /// <summary>
        /// Get a list of all accessible transaction manager objects.
        /// </summary>
        /// <returns>The list of all accessible transaction manager objects.</returns>
        public static IEnumerable<NtTransactionManager> GetAccessibleTransactionManager()
        {
            return GetAccessibleTransactionManager(TransactionManagerAccessRights.MaximumAllowed);
        }
        #endregion

        #region Public Properties

        /// <summary>
        /// Get the Transaction Manager identity.
        /// </summary>
        public Guid Identity => GetBasicInformation().TmIdentity;

        /// <summary>
        /// Get the Transaction Manager virtual clock.
        /// </summary>
        public long VirtualClock => GetBasicInformation().VirtualClock.QuadPart;

        /// <summary>
        /// Get the Transaction Manager log identity.
        /// </summary>
        public Guid LogIdentity => GetIdentity(true).Result;

        /// <summary>
        /// Get the Transaction Manager log path.
        /// </summary>
        public string LogPath => GetLogPath(true).Result;

        /// <summary>
        /// Get Transaction Manager last recovered Log Sequence Number.
        /// </summary>
        public ulong LastRecoveredLsn => Query<TransactionManagerRecoveryInformation>(TransactionManagerInformationClass.TransactionManagerRecoveryInformation).LastRecoveredLsn;

        /// <summary>
        /// Get whether the transaction manager is volatile.
        /// </summary>
        public bool Volatile
        {
            get
            {
                var log_path = GetLogPath(false);
                return !log_path.IsSuccess || string.IsNullOrEmpty(log_path.Result);
            }
        }

        #endregion

        #region Public Methods
        /// <summary>
        /// Rename transaction manager object. The new identity can be queried with the Identity property on the object.
        /// </summary>
        /// <param name="throw_on_error">True to throw an exception on error.</param>
        /// <returns>The NT status code</returns>
        public NtStatus Rename(bool throw_on_error)
        {
            return NtSystemCalls.NtRenameTransactionManager(GetLogPath(throw_on_error).Result.ToUnicodeString(),
               new OptionalGuid(GetIdentity(true).Result)).ToNtException(throw_on_error);
        }

        /// <summary>
        /// Rename transaction manager object. The new identity can be queried with the Identity property on the object.
        /// </summary>
        public void Rename()
        {
            Rename(true);
        }

        /// <summary>
        /// Recover the transaction manager.
        /// </summary>
        /// <param name="throw_on_error">True to throw an exception on error.</param>
        /// <returns>The NT status code</returns>
        public NtStatus Recover(bool throw_on_error)
        {
            return NtSystemCalls.NtRecoverTransactionManager(Handle).ToNtException(throw_on_error);
        }

        /// <summary>
        /// Recover the transaction manager.
        /// </summary>
        public void Recover()
        {
            Recover(true);
        }

        /// <summary>
        /// Rollforward the transaction manager.
        /// </summary>
        /// <param name="virtual_clock">Optional virtual block value to rollforward to.</param>
        /// <param name="throw_on_error">True to throw an exception on error.</param>
        /// <returns>The NT status code</returns>
        public NtStatus Rollforward(long? virtual_clock, bool throw_on_error)
        {
            return NtSystemCalls.NtRollforwardTransactionManager(Handle, virtual_clock.ToLargeInteger()).ToNtException(throw_on_error);
        }

        /// <summary>
        /// Rollforward the transaction manager.
        /// </summary>
        /// <param name="throw_on_error">True to throw an exception on error.</param>
        /// <returns>The NT status code</returns>
        public NtStatus Rollforward(bool throw_on_error)
        {
            return Rollforward(null, throw_on_error);
        }

        /// <summary>
        /// Rollforward the transaction manager.
        /// </summary>
        /// <param name="virtual_clock">Optional virtual block value to rollforward to.</param>
        public void Rollforward(long? virtual_clock)
        {
            Rollforward(virtual_clock, true);
        }

        /// <summary>
        /// Rollforward the transaction manager.
        /// </summary>
        public void Rollforward()
        {
            Rollforward(null);
        }

        /// <summary>
        /// Create a resource manager for this transaction manager.
        /// </summary>
        /// <param name="resource_manager_guid">The resource manager GUID to assign.</param>
        /// <param name="create_options">Creation options.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The resource manager and NT status.</returns>
        public NtResult<NtResourceManager> CreateResourceManager(Guid resource_manager_guid, ResourceManagerCreateOptions create_options, bool throw_on_error)
        {
            return NtResourceManager.Create(null, ResourceManagerAccessRights.MaximumAllowed, this, resource_manager_guid, create_options, null, throw_on_error);
        }

        /// <summary>
        /// Create a resource manager for this transaction manager.
        /// </summary>
        /// <param name="resource_manager_guid">The resource manager GUID to assign.</param>
        /// <param name="create_options">Creation options.</param>
        /// <returns>The resource manager .</returns>
        public NtResourceManager CreateResourceManager(Guid resource_manager_guid, ResourceManagerCreateOptions create_options)
        {
            return CreateResourceManager(resource_manager_guid, create_options, true).Result;
        }

        /// <summary>
        /// Create a resource manager for this transaction manager.
        /// </summary>
        /// <param name="resource_manager_guid">The resource manager GUID to assign.</param>
        /// <returns>The resource manager.</returns>
        public NtResourceManager CreateResourceManagerVolatile(Guid resource_manager_guid)
        {
            return CreateResourceManager(resource_manager_guid, ResourceManagerCreateOptions.Volatile, true).Result;
        }

        /// <summary>
        /// Create a volatile resource manager for this transaction manager with a auto-generated GUID.
        /// </summary>
        /// <returns>The resource manager.</returns>
        public NtResourceManager CreateResourceManagerVolatile()
        {
            return CreateResourceManagerVolatile(Guid.NewGuid());
        }

        /// <summary>
        /// Method to query information for this object type.
        /// </summary>
        /// <param name="info_class">The information class.</param>
        /// <param name="buffer">The buffer to return data in.</param>
        /// <param name="return_length">Return length from the query.</param>
        /// <returns>The NT status code for the query.</returns>
        public override NtStatus QueryInformation(TransactionManagerInformationClass info_class, SafeBuffer buffer, out int return_length)
        {
            return NtSystemCalls.NtQueryInformationTransactionManager(Handle, info_class, buffer, buffer.GetLength(), out return_length);
        }

        /// <summary>
        /// Method to set information for this object type.
        /// </summary>
        /// <param name="info_class">The information class.</param>
        /// <param name="buffer">The buffer to set data from.</param>
        /// <returns>The NT status code for the set.</returns>
        public override NtStatus SetInformation(TransactionManagerInformationClass info_class, SafeBuffer buffer)
        {
            return NtSystemCalls.NtSetInformationTransactionManager(Handle, info_class, buffer, buffer.GetLength());
        }

        /// <summary>
        /// Get a list of all accessible transaction objects owned by this transaction manager.
        /// </summary>
        /// <param name="desired_access">The access for the transaction objects.</param>
        /// <returns>The list of all accessible transaction objects.</returns>
        public IEnumerable<NtTransaction> GetAccessibleTransaction(TransactionAccessRights desired_access)
        {
            return NtTransactionManagerUtils.GetAccessibleTransactionObjects(
                Handle,
                KtmObjectType.Transaction,
                id => NtTransaction.Open(null, desired_access, id, null, false));
        }

        /// <summary>
        /// Get a list of all accessible transaction objects owned by this transaction manager.
        /// </summary>
        /// <returns>The list of all accessible transaction objects.</returns>
        public IEnumerable<NtTransaction> GetAccessibleTransaction()
        {
            return GetAccessibleTransaction(TransactionAccessRights.MaximumAllowed);
        }

        /// <summary>
        /// Get a list of all accessible resource manager objects owned by this transaction manager.
        /// </summary>
        /// <param name="object_attributes">Object attributes for opened handle.</param>
        /// <param name="desired_access">The access for the resource manager objects.</param>
        /// <returns>The list of all accessible resource manager objects.</returns>
        public IEnumerable<NtResourceManager> GetAccessibleResourceManager(ObjectAttributes object_attributes, ResourceManagerAccessRights desired_access)
        {
            return NtTransactionManagerUtils.GetAccessibleTransactionObjects(
                Handle,
                KtmObjectType.ResourceManager,
                id => NtResourceManager.Open(object_attributes, desired_access, this, id, false));
        }

        /// <summary>
        /// Get a list of all accessible resource manager objects owned by this transaction manager.
        /// </summary>
        /// <param name="desired_access">The access for the resource manager objects.</param>
        /// <returns>The list of all accessible resource manager objects.</returns>
        public IEnumerable<NtResourceManager> GetAccessibleResourceManager(ResourceManagerAccessRights desired_access)
        {
            return GetAccessibleResourceManager(null, desired_access);
        }

        /// <summary>
        /// Get a list of all accessible resource manager objects owned by this transaction manager.
        /// </summary>
        /// <returns>The list of all accessible resource manager objects.</returns>
        public IEnumerable<NtResourceManager> GetAccessibleResourceManager()
        {
            return GetAccessibleResourceManager(ResourceManagerAccessRights.MaximumAllowed);
        }

        #endregion

        #region Private Members

        private TransactionManagerBasicInformation GetBasicInformation()
        {
            return Query<TransactionManagerBasicInformation>(TransactionManagerInformationClass.TransactionManagerBasicInformation);
        }

        private NtResult<Guid> GetIdentity(bool throw_on_error)
        {
            return Query(TransactionManagerInformationClass.TransactionManagerLogInformation, 
                new TransactionManagerLogInformation(), throw_on_error).Map(i => i.LogIdentity);
        }

        private NtResult<string> GetLogPath(bool throw_on_error)
        {
            using (var buffer = QueryBuffer(TransactionManagerInformationClass.TransactionManagerLogPathInformation, 
                new TransactionLogPathInformation(), throw_on_error))
            {
                return buffer.Map(i => i.Data.ReadUnicodeString(i.Result.LogPathLength / 2));
            }
        }

        #endregion
    }
}
