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
using System.Runtime.InteropServices;

namespace NtApiDotNet
{
#pragma warning disable 1591
    [Flags]
    public enum ResourceManagerAccessRights : uint
    {
        QueryInformation = 1,
        SetInformation = 2,
        Recover = 4,
        Enlist = 8,
        GetNotification = 0x10,
        RegisterProtocol = 0x20,
        CompletePropagation = 0x40,
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

    public enum ResourceManagerCreateOptions
    {
        None = 0,
        Volatile = 1,
        Communication = 2,
    }

    [Flags]
    public enum TransactionNotifyMask : uint
    {
        PrePrepare = 0x00000001,
        Prepare = 0x00000002,
        Commit = 0x00000004,
        Rollback = 0x00000008,
        PrePrepareComplete = 0x00000010,
        PrepareComplete = 0x00000020,
        CommitComplete = 0x00000040,
        RollbackComplete = 0x00000080,
        Recover = 0x00000100,
        SinglePhaseCommit = 0x00000200,
        DelegateCommit = 0x00000400,
        RecoverQuery = 0x00000800,
        EnlistPrePrepare = 0x00001000,
        LastRecover = 0x00002000,
        InDoubt = 0x00004000,
        PropagatePull = 0x00008000,
        PropagatePush = 0x00010000,
        Marshal = 0x00020000,
        EnlistMask = 0x00040000,
        RmDisconnected = 0x01000000,
        TmOnline = 0x02000000,
        CommitRequest = 0x04000000,
        Promote = 0x08000000,
        PromoteNew = 0x10000000,
        RequestOutcome = 0x20000000,
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct TransactionNotificationData
    {
        public IntPtr TransactionKey;
        public TransactionNotifyMask TransactionNotification;
        public LargeIntegerStruct TmVirtualClock;
        public int ArgumentLength;
    }

    public enum ResourceManagerInformationClass
    {
        ResourceManagerBasicInformation,
        ResourceManagerCompletionInformation
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode), DataStart("Description")]
    public struct ResourceManagerBasicInformation
    {
        public Guid ResourceManagerId;
        public int DescriptionLength;
        public char Description;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct ResourceManagerCompletionInformation
    {
        public IntPtr IoCompletionPortHandle;
        public IntPtr CompletionKey;
    }

    public static partial class NtSystemCalls
    {
        [DllImport("ntdll.dll")]
        public static extern NtStatus NtCreateResourceManager(
            out SafeKernelObjectHandle ResourceManagerHandle,
            ResourceManagerAccessRights DesiredAccess,
            SafeKernelObjectHandle TmHandle,
            OptionalGuid RmGuid,
            ObjectAttributes ObjectAttributes,
            ResourceManagerCreateOptions CreateOptions,
            UnicodeString Description
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtOpenResourceManager(
            out SafeKernelObjectHandle ResourceManagerHandle,
            ResourceManagerAccessRights DesiredAccess,
            SafeKernelObjectHandle TmHandle,
            OptionalGuid ResourceManagerGuid,
            ObjectAttributes ObjectAttributes
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtQueryInformationResourceManager(
            SafeKernelObjectHandle ResourceManagerHandle,
            ResourceManagerInformationClass ResourceManagerInformationClass,
            SafeBuffer ResourceManagerInformation,
            int ResourceManagerInformationLength,
            out int ReturnLength
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtSetInformationResourceManager(
            SafeKernelObjectHandle ResourceManagerHandle,
            ResourceManagerInformationClass ResourceManagerInformationClass,
            SafeBuffer ResourceManagerInformation,
            int ResourceManagerInformationLength
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtRecoverResourceManager(
            SafeKernelObjectHandle ResourceManagerHandle
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtGetNotificationResourceManager(
            SafeKernelObjectHandle ResourceManagerHandle,
            SafeBuffer TransactionNotification, // Allocated TransactionNotificationData
            int NotificationLength,
            LargeInteger Timeout,
            out int ReturnLength,
            int Asynchronous,
            IntPtr AsynchronousContext
        );
    }

#pragma warning restore 1591
    /// <summary>
    /// Class to represent a transaction resource manager.
    /// </summary>
    public sealed class NtResourceManager : NtObjectWithDuplicateAndInfo<NtResourceManager, ResourceManagerAccessRights, ResourceManagerInformationClass>
    {
        #region Constructors
        internal NtResourceManager(SafeKernelObjectHandle handle) 
            : base(handle)
        {
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
        /// <param name="resource_manager_guid">Optional resource manager GUID.</param>
        /// <param name="description">Optional description.</param>
        /// <param name="throw_on_error">True to throw an exception on error.</param>
        /// <returns>The NT status code and object result.</returns>
        public static NtResult<NtResourceManager> Create(ObjectAttributes object_attributes,
                ResourceManagerAccessRights desired_access,
                NtTransactionManager transaction_manager,
                Guid? resource_manager_guid,
                ResourceManagerCreateOptions create_options,
                string description,
                bool throw_on_error)
        {
            return NtSystemCalls.NtCreateResourceManager(out SafeKernelObjectHandle handle,
                desired_access, transaction_manager.GetHandle(), resource_manager_guid.ToOptional(),
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
        /// <param name="resource_manager_guid">Optional resource manager GUID.</param>
        /// <param name="description">Optional description.</param>
        /// <returns>The object result.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static NtResourceManager Create(ObjectAttributes object_attributes,
                ResourceManagerAccessRights desired_access,
                NtTransactionManager transaction_manager,
                Guid? resource_manager_guid,
                ResourceManagerCreateOptions create_options,
                string description)
        {
            return Create(object_attributes, desired_access, transaction_manager, 
                resource_manager_guid, create_options, description, true).Result;
        }

        /// <summary>
        /// Opens an existing resource manager object.
        /// </summary>
        /// <param name="object_attributes">The object attributes</param>
        /// <param name="desired_access">Desired access for the handle</param>
        /// <param name="transaction_manager">Optional transaction manager which contains the resource manager.</param>
        /// <param name="resource_manager_guid">Optional resource manager GUID.</param>
        /// <param name="throw_on_error">True to throw an exception on error.</param>
        /// <returns>The NT status code and object result.</returns>
        public static NtResult<NtResourceManager> Open(ObjectAttributes object_attributes,
                ResourceManagerAccessRights desired_access,
                NtTransactionManager transaction_manager,
                Guid? resource_manager_guid,
                bool throw_on_error)
        {
            return NtSystemCalls.NtOpenResourceManager(out SafeKernelObjectHandle handle,
                desired_access, transaction_manager.GetHandle(), resource_manager_guid.ToOptional(),
                object_attributes).CreateResult(throw_on_error, () => new NtResourceManager(handle));
        }

        /// <summary>
        /// Opens an existing resource manager object.
        /// </summary>
        /// <param name="object_attributes">The object attributes</param>
        /// <param name="desired_access">Desired access for the handle</param>
        /// <param name="transaction_manager">Optional transaction manager which contains the resource manager.</param>
        /// <param name="resource_manager_guid">Optional resource manager GUID.</param>
        /// <returns>The object result.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static NtResourceManager Open(ObjectAttributes object_attributes,
                ResourceManagerAccessRights desired_access,
                NtTransactionManager transaction_manager,
                Guid? resource_manager_guid)
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
    }
}
