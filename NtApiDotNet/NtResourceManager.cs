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
    /// Class to represent a transaction resource manager.
    /// </summary>
    [NtType("TmRm")]
    public sealed class NtResourceManager : NtObjectWithDuplicateAndInfo<NtResourceManager, ResourceManagerAccessRights, 
                                    ResourceManagerInformationClass, ResourceManagerInformationClass>
    {
        #region Constructors

        internal NtResourceManager(SafeKernelObjectHandle handle) 
            : base(handle)
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
        /// Create a new resource manager object.
        /// </summary>
        /// <param name="object_attributes">The object attributes</param>
        /// <param name="desired_access">Desired access for the handle</param>
        /// <param name="create_options">Creation options flags.</param>
        /// <param name="transaction_manager">Optional transaction manager to assign the resource manager to.</param>
        /// <param name="resource_manager_guid">Resource manager GUID.</param>
        /// <param name="description">Optional description.</param>
        /// <param name="throw_on_error">True to throw an exception on error.</param>
        /// <returns>The NT status code and object result.</returns>
        public static NtResult<NtResourceManager> Create(ObjectAttributes object_attributes,
                ResourceManagerAccessRights desired_access,
                NtTransactionManager transaction_manager,
                Guid resource_manager_guid,
                ResourceManagerCreateOptions create_options,
                string description,
                bool throw_on_error)
        {
            return NtSystemCalls.NtCreateResourceManager(out SafeKernelObjectHandle handle,
                desired_access, transaction_manager.GetHandle(), ref resource_manager_guid,
                object_attributes, create_options, description.ToUnicodeString())
                .CreateResult(throw_on_error, () => new NtResourceManager(handle));
        }

        /// <summary>
        /// Create a new resource manager object.
        /// </summary>
        /// <param name="object_attributes">The object attributes</param>
        /// <param name="desired_access">Desired access for the handle</param>
        /// <param name="create_options">Creation options flags.</param>
        /// <param name="transaction_manager">Optional transaction manager to assign the resource manager to.</param>
        /// <param name="resource_manager_guid">Resource manager GUID.</param>
        /// <param name="description">Optional description.</param>
        /// <returns>The object result.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static NtResourceManager Create(ObjectAttributes object_attributes,
                ResourceManagerAccessRights desired_access,
                NtTransactionManager transaction_manager,
                Guid resource_manager_guid,
                ResourceManagerCreateOptions create_options,
                string description)
        {
            return Create(object_attributes, desired_access, transaction_manager, 
                resource_manager_guid, create_options, description, true).Result;
        }

        /// <summary>
        /// Create a new resource manager object.
        /// </summary>
        /// <param name="path">The path to the resource manager.</param>
        /// <param name="root">The root if path is relative.</param>
        /// <param name="desired_access">Desired access for the handle</param>
        /// <param name="create_options">Creation options flags.</param>
        /// <param name="transaction_manager">Optional transaction manager to assign the resource manager to.</param>
        /// <param name="resource_manager_guid">Resource manager GUID.</param>
        /// <param name="description">Optional description.</param>
        /// <param name="throw_on_error">True to throw an exception on error.</param>
        /// <returns>The NT status code and object result.</returns>
        public static NtResult<NtResourceManager> Create(string path,
                NtObject root,
                ResourceManagerAccessRights desired_access,
                NtTransactionManager transaction_manager,
                Guid resource_manager_guid,
                ResourceManagerCreateOptions create_options,
                string description,
                bool throw_on_error)
        {
            using (var obj_attr = new ObjectAttributes(path, AttributeFlags.CaseInsensitive, root))
            {
                return Create(obj_attr, desired_access, transaction_manager, 
                    resource_manager_guid, create_options, description, throw_on_error);
            }
        }

        /// <summary>
        /// Create a new resource manager object.
        /// </summary>
        /// <param name="path">The path to the resource manager.</param>
        /// <param name="root">The root if path is relative.</param>
        /// <param name="desired_access">Desired access for the handle</param>
        /// <param name="create_options">Creation options flags.</param>
        /// <param name="transaction_manager">Optional transaction manager to assign the resource manager to.</param>
        /// <param name="resource_manager_guid">Resource manager GUID.</param>
        /// <param name="description">Optional description.</param>
        /// <returns>The object result.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static NtResourceManager Create(string path,
                NtObject root,
                ResourceManagerAccessRights desired_access,
                NtTransactionManager transaction_manager,
                Guid resource_manager_guid,
                ResourceManagerCreateOptions create_options = ResourceManagerCreateOptions.None,
                string description = null)
        {
            return Create(path, root, desired_access, transaction_manager,
                resource_manager_guid, create_options, description, true).Result;
        }

        /// <summary>
        /// Create a new volatile resource manager object.
        /// </summary>
        /// <param name="path">The path to the resource manager.</param>
        /// <param name="root">The root if path is relative.</param>
        /// <param name="desired_access">Desired access for the handle</param>
        /// <param name="transaction_manager">Optional transaction manager to assign the resource manager to.</param>
        /// <param name="resource_manager_guid">Resource manager GUID.</param>
        /// <returns>The object result.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static NtResourceManager CreateVolatile(string path,
                NtObject root,
                ResourceManagerAccessRights desired_access,
                NtTransactionManager transaction_manager,
                Guid resource_manager_guid)
        {
            return Create(path, root, desired_access, transaction_manager,
                resource_manager_guid, ResourceManagerCreateOptions.Volatile, null, true).Result;
        }

        /// <summary>
        /// Create a new volatile resource manager object.
        /// </summary>
        /// <param name="path">The path to the resource manager.</param>
        /// <param name="root">The root if path is relative.</param>
        /// <param name="desired_access">Desired access for the handle</param>
        /// <param name="transaction_manager">Optional transaction manager to assign the resource manager to.</param>
        /// <returns>The object result.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static NtResourceManager CreateVolatile(string path,
                NtObject root,
                ResourceManagerAccessRights desired_access,
                NtTransactionManager transaction_manager)
        {
            return CreateVolatile(path, null, ResourceManagerAccessRights.MaximumAllowed, 
                transaction_manager, Guid.NewGuid());
        }

        /// <summary>
        /// Create a new volatile resource manager object.
        /// </summary>
        /// <param name="path">The path to the resource manager.</param>
        /// <param name="root">The root if path is relative.</param>
        /// <param name="transaction_manager">Optional transaction manager to assign the resource manager to.</param>
        /// <returns>The object result.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static NtResourceManager CreateVolatile(string path,
                NtObject root,
                NtTransactionManager transaction_manager)
        {
            return CreateVolatile(path, null, ResourceManagerAccessRights.MaximumAllowed, transaction_manager);
        }

        /// <summary>
        /// Create a new volatile resource manager object.
        /// </summary>
        /// <param name="path">The path to the resource manager.</param>
        /// <param name="transaction_manager">Optional transaction manager to assign the resource manager to.</param>
        /// <returns>The object result.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static NtResourceManager CreateVolatile(string path,
                NtTransactionManager transaction_manager)
        {
            return CreateVolatile(path, null, transaction_manager);
        }

        /// <summary>
        /// Create a new volatile resource manager object.
        /// </summary>
        /// <param name="transaction_manager">Optional transaction manager to assign the resource manager to.</param>
        /// <returns>The object result.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static NtResourceManager CreateVolatile(NtTransactionManager transaction_manager)
        {
            return CreateVolatile(null, transaction_manager);
        }

        /// <summary>
        /// Opens an existing resource manager object.
        /// </summary>
        /// <param name="object_attributes">The object attributes</param>
        /// <param name="desired_access">Desired access for the handle</param>
        /// <param name="transaction_manager">Transaction manager which contains the resource manager.</param>
        /// <param name="resource_manager_guid">Resource manager GUID.</param>
        /// <param name="throw_on_error">True to throw an exception on error.</param>
        /// <returns>The NT status code and object result.</returns>
        public static NtResult<NtResourceManager> Open(ObjectAttributes object_attributes,
                ResourceManagerAccessRights desired_access,
                NtTransactionManager transaction_manager,
                Guid resource_manager_guid,
                bool throw_on_error)
        {
            return NtSystemCalls.NtOpenResourceManager(out SafeKernelObjectHandle handle,
                desired_access, transaction_manager.GetHandle(), ref resource_manager_guid,
                object_attributes).CreateResult(throw_on_error, () => new NtResourceManager(handle));
        }

        /// <summary>
        /// Opens an existing resource manager object.
        /// </summary>
        /// <param name="object_attributes">The object attributes</param>
        /// <param name="desired_access">Desired access for the handle</param>
        /// <param name="transaction_manager">Transaction manager which contains the resource manager.</param>
        /// <param name="resource_manager_guid">Resource manager GUID.</param>
        /// <returns>The object result.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static NtResourceManager Open(ObjectAttributes object_attributes,
                ResourceManagerAccessRights desired_access,
                NtTransactionManager transaction_manager,
                Guid resource_manager_guid)
        {
            return Open(object_attributes, desired_access, transaction_manager,
                resource_manager_guid, true).Result;
        }

        #endregion

        #region Public Methods

        /// <summary>
        /// Recover the the transaction manager.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public NtStatus Recover(bool throw_on_error)
        {
            return NtSystemCalls.NtRecoverResourceManager(Handle).ToNtException(throw_on_error);
        }

        /// <summary>
        /// Recover the the transaction manager.
        /// </summary>
        public void Recover()
        {
            Recover(true);
        }

        /// <summary>
        /// Set an IO completion port on the resource manager.
        /// </summary>
        /// <param name="io_completion">The IO completion port.</param>
        /// <param name="completion_key">Associated completion key.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public NtStatus SetIoCompletion(NtIoCompletion io_completion, IntPtr completion_key, bool throw_on_error)
        {
            return Set(ResourceManagerInformationClass.ResourceManagerCompletionInformation, 
                new ResourceManagerCompletionInformation() {
                    IoCompletionPortHandle = io_completion.Handle.DangerousGetHandle(),
                    CompletionKey = completion_key }, throw_on_error);
        }

        /// <summary>
        /// Set an IO completion port on the resource manager.
        /// </summary>
        /// <param name="io_completion">The IO completion port.</param>
        /// <param name="completion_key">Associated completion key.</param>
        public void SetIoCompletion(NtIoCompletion io_completion, IntPtr completion_key)
        {
            SetIoCompletion(io_completion, completion_key, true);
        }

        /// <summary>
        /// Get a notification synchronously.
        /// </summary>
        /// <param name="timeout">Optional timeout for getting the notification.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The transaction notification.</returns>
        public NtResult<TransactionNotification> GetNotification(NtWaitTimeout timeout, bool throw_on_error)
        {
            NtStatus status = NtSystemCalls.NtGetNotificationResourceManager(Handle, 
                SafeHGlobalBuffer.Null, 0, timeout.ToLargeInteger(), out int return_length, 0, IntPtr.Zero);
            if (status != NtStatus.STATUS_BUFFER_TOO_SMALL)
            {
                return status.CreateResultFromError<TransactionNotification>(throw_on_error);
            }

            using (var buffer = new SafeStructureInOutBuffer<TransactionNotificationData>(return_length, false))
            {
                return NtSystemCalls.NtGetNotificationResourceManager(Handle,
                    buffer, buffer.Length, timeout.ToLargeInteger(), out return_length, 0, IntPtr.Zero)
                    .CreateResult(throw_on_error, () => new TransactionNotification(buffer));
            }
        }

        /// <summary>
        /// Get a notification synchronously.
        /// </summary>
        /// <param name="timeout">Optional timeout for getting the notification.</param>
        /// <returns>The transaction notification.</returns>
        public TransactionNotification GetNotification(NtWaitTimeout timeout)
        {
            return GetNotification(timeout, true).Result;
        }

        /// <summary>
        /// Get a notification synchronously waiting indefinetly.
        /// </summary>
        /// <returns>The transaction notification.</returns>
        public TransactionNotification GetNotification()
        {
            return GetNotification(NtWaitTimeout.Infinite);
        }

        /// <summary>
        /// Register protocol information.
        /// </summary>
        /// <param name="protocol_id">The ID of the protocol to register.</param>
        /// <param name="protocol_information">An opaque protocol buffer.</param>
        /// <param name="create_options">Optional create options.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public NtStatus RegisterProtocolAddressInformation(Guid protocol_id,
            byte[] protocol_information, RegisterProtocolCreateOptions create_options, bool throw_on_error)
        {
            using (var buffer = protocol_information.ToBuffer())
            {
                return NtSystemCalls.NtRegisterProtocolAddressInformation(Handle,
                    ref protocol_id, buffer.Length, buffer, create_options).ToNtException(throw_on_error);
            }
        }

        /// <summary>
        /// Register protocol information.
        /// </summary>
        /// <param name="protocol_id">The ID of the protocol to register.</param>
        /// <param name="protocol_information">An opaque protocol buffer.</param>
        /// <param name="create_options">Optional create options.</param>
        public void RegisterProtocolAddressInformation(Guid protocol_id,
            byte[] protocol_information, RegisterProtocolCreateOptions create_options = RegisterProtocolCreateOptions.None)
        {
            RegisterProtocolAddressInformation(protocol_id, protocol_information, create_options, true);
        }

        /// <summary>
        /// Complete propagation request.
        /// </summary>
        /// <param name="request_cookie">The cookie to identify the request.</param>
        /// <param name="request_buffer">An optional buffer to pass with the request.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public NtStatus PropagationComplete(uint request_cookie, byte[] request_buffer, bool throw_on_error)
        {
            using (var buffer = request_buffer.ToBuffer())
            {
                return NtSystemCalls.NtPropagationComplete(Handle, 
                    request_cookie, buffer.Length, buffer).ToNtException(throw_on_error);
            }
        }

        /// <summary>
        /// Complete propagation request.
        /// </summary>
        /// <param name="request_cookie">The cookie to identify the request.</param>
        /// <param name="request_buffer">An optional buffer to pass with the request.</param>
        public void PropagationComplete(uint request_cookie, byte[] request_buffer)
        {
            PropagationComplete(request_cookie, request_buffer, true);
        }

        /// <summary>
        /// Fail propagation request.
        /// </summary>
        /// <param name="request_cookie">The cookie to identify the request.</param>
        /// <param name="prop_status">Optional NT status code for the failure.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public NtStatus PropagationFailed(uint request_cookie, NtStatus prop_status, bool throw_on_error)
        {
            return NtSystemCalls.NtPropagationFailed(Handle, request_cookie, prop_status).ToNtException(throw_on_error);
        }

        /// <summary>
        /// Get a list of all accessible enlistment objects owned by this resource manager.
        /// </summary>
        /// <param name="object_attributes">The object attributes</param>
        /// <param name="desired_access">The access for the enlistment objects.</param>
        /// <returns>The list of all accessible enlistment objects.</returns>
        public IEnumerable<NtEnlistment> GetAccessibleEnlistment(ObjectAttributes object_attributes, EnlistmentAccessRights desired_access)
        {
            return NtTransactionManagerUtils.GetAccessibleTransactionObjects(
                Handle,
                KtmObjectType.Enlistment,
                id => NtEnlistment.Open(object_attributes, desired_access, this, id, false));
        }

        /// <summary>
        /// Get a list of all accessible enlistment objects owned by this resource manager.
        /// </summary>
        /// <param name="desired_access">The access for the enlistment objects.</param>
        /// <returns>The list of all accessible enlistment objects.</returns>
        public IEnumerable<NtEnlistment> GetAccessibleEnlistment(EnlistmentAccessRights desired_access)
        {
            return GetAccessibleEnlistment(null, desired_access);
        }

        /// <summary>
        /// Get a list of all accessible resource manager objects owned by this transaction manager.
        /// </summary>
        /// <returns>The list of all accessible resource manager objects.</returns>
        public IEnumerable<NtEnlistment> GetAccessibleEnlistment()
        {
            return GetAccessibleEnlistment(EnlistmentAccessRights.MaximumAllowed);
        }

        /// <summary>
        /// Create an enlistment in this resource manager.
        /// </summary>
        /// <param name="desired_access">Desired access for the handle</param>
        /// <param name="transaction">The transaction to enlist.</param>
        /// <param name="create_options">Optional create options.</param>
        /// <param name="notification_mask">Notification mask.</param>
        /// <param name="enlistment_key">Enlistment key returned during notification.</param>
        /// <param name="throw_on_error">True to throw an exception on error.</param>
        /// <returns>The created enlistment and NT status code.</returns>
        public NtResult<NtEnlistment> CreateEnlistment(EnlistmentAccessRights desired_access, NtTransaction transaction, 
            EnlistmentCreateOptions create_options, TransactionNotificationMask notification_mask, IntPtr enlistment_key, bool throw_on_error)
        {
            return NtEnlistment.Create(null, desired_access, this, transaction, 
                create_options, notification_mask, enlistment_key, throw_on_error);
        }

        /// <summary>
        /// Create an enlistment in this resource manager.
        /// </summary>
        /// <param name="desired_access">Desired access for the handle</param>
        /// <param name="transaction">The transaction to enlist.</param>
        /// <param name="create_options">Optional create options.</param>
        /// <param name="notification_mask">Notification mask.</param>
        /// <param name="enlistment_key">Enlistment key returned during notification.</param>
        /// <returns>The created enlistment.</returns>
        public NtEnlistment CreateEnlistment(EnlistmentAccessRights desired_access, NtTransaction transaction,
            EnlistmentCreateOptions create_options, TransactionNotificationMask notification_mask, IntPtr enlistment_key)
        {
            return CreateEnlistment(desired_access, transaction,
                create_options, notification_mask, enlistment_key, true).Result;
        }

        /// <summary>
        /// Create an enlistment in this resource manager.
        /// </summary>
        /// <param name="transaction">The transaction to enlist.</param>
        /// <param name="notification_mask">Notification mask.</param>
        /// <param name="enlistment_key">Enlistment key returned during notification.</param>
        /// <returns>The created enlistment.</returns>
        public NtEnlistment CreateEnlistment(NtTransaction transaction,
            TransactionNotificationMask notification_mask, IntPtr enlistment_key)
        {
            return CreateEnlistment(EnlistmentAccessRights.MaximumAllowed, transaction,
                EnlistmentCreateOptions.None, notification_mask, enlistment_key, true).Result;
        }

        /// <summary>
        /// Create an enlistment in this resource manager.
        /// </summary>
        /// <param name="transaction">The transaction to enlist.</param>
        /// <param name="enlistment_key">Enlistment key returned during notification.</param>
        /// <returns>The created enlistment.</returns>
        public NtEnlistment CreateEnlistment(NtTransaction transaction, IntPtr enlistment_key)
        {
            return CreateEnlistment(EnlistmentAccessRights.MaximumAllowed, transaction,
                EnlistmentCreateOptions.None, NtEnlistment.GetDefaultMaskForCreateOption(EnlistmentCreateOptions.None), 
                enlistment_key, true).Result;
        }

        /// <summary>
        /// Method to query information for this object type.
        /// </summary>
        /// <param name="info_class">The information class.</param>
        /// <param name="buffer">The buffer to return data in.</param>
        /// <param name="return_length">Return length from the query.</param>
        /// <returns>The NT status code for the query.</returns>
        public override NtStatus QueryInformation(ResourceManagerInformationClass info_class, SafeBuffer buffer, out int return_length)
        {
            return NtSystemCalls.NtQueryInformationResourceManager(Handle, info_class, buffer, buffer.GetLength(), out return_length);
        }

        /// <summary>
        /// Method to set information for this object type.
        /// </summary>
        /// <param name="info_class">The information class.</param>
        /// <param name="buffer">The buffer to set data from.</param>
        /// <returns>The NT status code for the set.</returns>
        public override NtStatus SetInformation(ResourceManagerInformationClass info_class, SafeBuffer buffer)
        {
            return NtSystemCalls.NtSetInformationResourceManager(Handle, info_class, buffer, buffer.GetLength());
        }
        #endregion

        #region Public Properties
        /// <summary>
        /// Get the resource manager ID.
        /// </summary>
        public Guid ResourceManagerId => QueryBasicInformation().ResourceManagerId;

        /// <summary>
        /// Get the description for the resource manager.
        /// </summary>
        public string Description => QueryDescription();
        #endregion

        #region Private Members
        private SafeStructureInOutBuffer<ResourceManagerBasicInformation> QueryBasicInformationBuffer()
        {
            return QueryBuffer<ResourceManagerBasicInformation>(ResourceManagerInformationClass.ResourceManagerBasicInformation);
        }

        private string QueryDescription()
        {
            using (var buffer = QueryBasicInformationBuffer())
            {
                return buffer.Data.ReadUnicodeString(buffer.Result.DescriptionLength / 2);
            }
        }

        private ResourceManagerBasicInformation QueryBasicInformation()
        {
            using (var buffer = QueryBasicInformationBuffer())
            {
                return buffer.Result;
            }
        }

        #endregion
    }
}
