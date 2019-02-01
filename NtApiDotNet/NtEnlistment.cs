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
    public enum EnlistmentAccessRights : uint
    {
        None = 0,
        QueryInformation = 1,
        SetInformation = 2,
        Recover = 4,
        SubordinateRights = 8,
        SuperiorRights = 0x10,
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
    public enum EnlistmentCreateOptions
    {
        None = 0,
        Superior = 1,
    }

    public enum EnlistmentInformationClass
    {
        EnlistmentBasicInformation,
        EnlistmentRecoveryInformation,
        EnlistmentCrmInformation
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct EnlistmentBasicInformation
    {
        public Guid EnlistmentId;
        public Guid TransactionId;
        public Guid ResourceManagerId;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct EnlistmentCrmInformation
    {
        public Guid CrmTransactionManagerId;
        public Guid CrmResourceManagerId;
        public Guid CrmEnlistmentId;
    }

    public static partial class NtSystemCalls
    {
        [DllImport("ntdll.dll")]
        public static extern NtStatus NtCreateEnlistment(
            out SafeKernelObjectHandle EnlistmentHandle,
            EnlistmentAccessRights DesiredAccess,
            SafeKernelObjectHandle ResourceManagerHandle,
            SafeKernelObjectHandle TransactionHandle,
            ObjectAttributes ObjectAttributes,
            EnlistmentCreateOptions CreateOptions,
            TransactionNotificationMask NotificationMask,
            IntPtr EnlistmentKey
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtOpenEnlistment(
            out SafeKernelObjectHandle EnlistmentHandle,
            EnlistmentAccessRights DesiredAccess,
            SafeKernelObjectHandle ResourceManagerHandle,
            OptionalGuid EnlistmentGuid,
            ObjectAttributes ObjectAttributes
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtCommitComplete(
            SafeKernelObjectHandle EnlistmentHandle,
            LargeInteger TmVirtualClock
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtCommitEnlistment(
            SafeKernelObjectHandle EnlistmentHandle,
            LargeInteger TmVirtualClock
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtPrePrepareComplete(
            SafeKernelObjectHandle EnlistmentHandle,
            LargeInteger TmVirtualClock
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtPrePrepareEnlistment(
            SafeKernelObjectHandle EnlistmentHandle,
            LargeInteger TmVirtualClock
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtPrepareComplete(
            SafeKernelObjectHandle EnlistmentHandle,
            LargeInteger TmVirtualClock
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtPrepareEnlistment(
            SafeKernelObjectHandle EnlistmentHandle,
            LargeInteger TmVirtualClock
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtRollbackComplete(
            SafeKernelObjectHandle EnlistmentHandle,
            LargeInteger TmVirtualClock
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtRollbackEnlistment(
            SafeKernelObjectHandle EnlistmentHandle,
            LargeInteger TmVirtualClock
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtReadOnlyEnlistment(
            SafeKernelObjectHandle EnlistmentHandle,
            LargeInteger TmVirtualClock
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtRecoverEnlistment(
            SafeKernelObjectHandle EnlistmentHandle,
            LargeInteger TmVirtualClock
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtSinglePhaseReject(
            SafeKernelObjectHandle EnlistmentHandle,
            LargeInteger TmVirtualClock
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtQueryInformationEnlistment(
            SafeKernelObjectHandle EnlistmentHandle,
            EnlistmentInformationClass EnlistmentInformationClass,
            SafeBuffer EnlistmentInformation,
            int EnlistmentInformationLength,
            out int ReturnLength
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtSetInformationEnlistment(
            SafeKernelObjectHandle EnlistmentHandle,
            EnlistmentInformationClass EnlistmentInformationClass,
            SafeBuffer EnlistmentInformation,
            int EnlistmentInformationLength
        );
    }

#pragma warning restore 1591

    /// <summary>
    /// Class to represent a kernel transaction enlistment.
    /// </summary>
    [NtType("TmEn")]
    public class NtEnlistment : NtObjectWithDuplicateAndInfo<NtEnlistment, EnlistmentAccessRights, EnlistmentInformationClass>
    {
        #region Constructors
        internal NtEnlistment(SafeKernelObjectHandle handle) : base(handle)
        {
        }
        #endregion

        #region Static Methods

        /// <summary>
        /// Create a new enlistment object.
        /// </summary>
        /// <param name="object_attributes">The object attributes</param>
        /// <param name="desired_access">Desired access for the handle</param>
        /// <param name="resource_manager">Resource manager to handle the enlistment.</param>
        /// <param name="transaction">The transaction to enlist.</param>
        /// <param name="create_options">Optional create options.</param>
        /// <param name="notification_mask">Notification mask.</param>
        /// <param name="enlistment_key">Enlistment key returned during notification.</param>
        /// <param name="throw_on_error">True to throw an exception on error.</param>
        /// <returns>The created enlistment and NT status code.</returns>
        public static NtResult<NtEnlistment> Create(
            ObjectAttributes object_attributes,
            EnlistmentAccessRights desired_access,
            NtResourceManager resource_manager,
            NtTransaction transaction,
            EnlistmentCreateOptions create_options,
            TransactionNotificationMask notification_mask,
            IntPtr enlistment_key,
            bool throw_on_error
            )
        {
            return NtSystemCalls.NtCreateEnlistment(out SafeKernelObjectHandle handle,
                desired_access,
                resource_manager.GetHandle(),
                transaction.GetHandle(),
                object_attributes,
                create_options,
                notification_mask,
                enlistment_key).CreateResult(throw_on_error, () => new NtEnlistment(handle));
        }

        /// <summary>
        /// Create a new enlistment object.
        /// </summary>
        /// <param name="object_attributes">The object attributes</param>
        /// <param name="desired_access">Desired access for the handle</param>
        /// <param name="resource_manager">Resource manager to handle the enlistment.</param>
        /// <param name="transaction">The transaction to enlist.</param>
        /// <param name="create_options">Optional create options.</param>
        /// <param name="notification_mask">Notification mask.</param>
        /// <param name="enlistment_key">Enlistment key returned during notification.</param>
        /// <returns>The created enlistment.</returns>
        public static NtEnlistment Create(
            ObjectAttributes object_attributes,
            EnlistmentAccessRights desired_access,
            NtResourceManager resource_manager,
            NtTransaction transaction,
            EnlistmentCreateOptions create_options,
            TransactionNotificationMask notification_mask,
            IntPtr enlistment_key
            )
        {
            return Create(object_attributes, desired_access,
                resource_manager, transaction,
                create_options, notification_mask,
                enlistment_key, true).Result;
        }

        /// <summary>
        /// Open a existing new enlistment object.
        /// </summary>
        /// <param name="object_attributes">The object attributes</param>
        /// <param name="desired_access">Desired access for the handle</param>
        /// <param name="resource_manager">Resource manager handling the enlistment.</param>
        /// <param name="enlistment_guid">ID of the enlistment to open.</param>
        /// <param name="throw_on_error">True to throw an exception on error.</param>
        /// <returns>The opened enlistment and NT status code.</returns>
        public static NtResult<NtEnlistment> Open(
            ObjectAttributes object_attributes,
            EnlistmentAccessRights desired_access,
            NtResourceManager resource_manager,
            Guid? enlistment_guid,
            bool throw_on_error
            )
        {
            return NtSystemCalls.NtOpenEnlistment(out SafeKernelObjectHandle handle,
                desired_access, resource_manager.GetHandle(),
                enlistment_guid.ToOptional(), object_attributes).CreateResult(throw_on_error, () => new NtEnlistment(handle));
        }

        /// <summary>
        /// Open a existing new enlistment object.
        /// </summary>
        /// <param name="object_attributes">The object attributes</param>
        /// <param name="desired_access">Desired access for the handle</param>
        /// <param name="resource_manager">Resource manager handling the enlistment.</param>
        /// <param name="enlistment_guid">ID of the enlistment to open.</param>
        /// <returns>The opened enlistment.</returns>
        public static NtEnlistment Open(
            ObjectAttributes object_attributes,
            EnlistmentAccessRights desired_access,
            NtResourceManager resource_manager,
            Guid? enlistment_guid
            )
        {
            return Open(object_attributes, desired_access, resource_manager, enlistment_guid, true).Result;
        }

        /// <summary>
        /// Get a default mask for creating an enlistment object.
        /// </summary>
        /// <param name="create_options">The creation option to get default mask for.</param>
        /// <returns>A default working mask.</returns>
        public static TransactionNotificationMask GetDefaultMaskForCreateOption(EnlistmentCreateOptions create_options)
        {
            switch (create_options)
            {
                case EnlistmentCreateOptions.None:
                    return TransactionNotificationMask.Rollback | TransactionNotificationMask.Commit | TransactionNotificationMask.Prepare |
                        TransactionNotificationMask.SinglePhaseCommit;
                case EnlistmentCreateOptions.Superior:
                    return TransactionNotificationMask.Rollback | TransactionNotificationMask.CommitComplete 
                        | TransactionNotificationMask.PrepareComplete | TransactionNotificationMask.PrePrepareComplete;
                default:
                    throw new ArgumentException("Invalid create options", nameof(create_options));
            }
        }

        #endregion

        #region Public Methods

        /// <summary>
        /// Commit complete enlistment.
        /// </summary>
        /// <param name="virtual_clock">Optional virtual clock value.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public NtStatus CommitComplete(long? virtual_clock, bool throw_on_error)
        {
            return NtSystemCalls.NtCommitComplete(Handle, virtual_clock.ToLargeInteger()).ToNtException(throw_on_error);
        }

        /// <summary>
        /// Commit enlistment.
        /// </summary>
        /// <param name="virtual_clock">Optional virtual clock value.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public NtStatus CommitEnlistment(long? virtual_clock, bool throw_on_error)
        {
            return NtSystemCalls.NtCommitEnlistment(Handle, virtual_clock.ToLargeInteger()).ToNtException(throw_on_error);
        }

        /// <summary>
        /// Preprepare complete enlistment.
        /// </summary>
        /// <param name="virtual_clock">Optional virtual clock value.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public NtStatus PrePrepareComplete(long? virtual_clock, bool throw_on_error)
        {
            return NtSystemCalls.NtPrePrepareComplete(Handle, virtual_clock.ToLargeInteger()).ToNtException(throw_on_error);
        }

        /// <summary>
        /// Preprepare enlistment.
        /// </summary>
        /// <param name="virtual_clock">Optional virtual clock value.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public NtStatus PrePrepareEnlistment(long? virtual_clock, bool throw_on_error)
        {
            return NtSystemCalls.NtPrePrepareEnlistment(Handle, virtual_clock.ToLargeInteger()).ToNtException(throw_on_error);
        }

        /// <summary>
        /// Prepare complete enlistment.
        /// </summary>
        /// <param name="virtual_clock">Optional virtual clock value.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public NtStatus PrepareComplete(long? virtual_clock, bool throw_on_error)
        {
            return NtSystemCalls.NtPrepareComplete(Handle, virtual_clock.ToLargeInteger()).ToNtException(throw_on_error);
        }

        /// <summary>
        /// Prepare enlistment.
        /// </summary>
        /// <param name="virtual_clock">Optional virtual clock value.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public NtStatus PrepareEnlistment(long? virtual_clock, bool throw_on_error)
        {
            return NtSystemCalls.NtPrepareEnlistment(Handle, virtual_clock.ToLargeInteger()).ToNtException(throw_on_error);
        }

        /// <summary>
        /// Rollback complete enlistment.
        /// </summary>
        /// <param name="virtual_clock">Optional virtual clock value.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public NtStatus RollbackComplete(long? virtual_clock, bool throw_on_error)
        {
            return NtSystemCalls.NtRollbackComplete(Handle, virtual_clock.ToLargeInteger()).ToNtException(throw_on_error);
        }

        /// <summary>
        /// Rollback enlistment.
        /// </summary>
        /// <param name="virtual_clock">Optional virtual clock value.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public NtStatus RollbackEnlistment(long? virtual_clock, bool throw_on_error)
        {
            return NtSystemCalls.NtRollbackEnlistment(Handle, virtual_clock.ToLargeInteger()).ToNtException(throw_on_error);
        }

        /// <summary>
        /// Read only enlistment.
        /// </summary>
        /// <param name="virtual_clock">Optional virtual clock value.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public NtStatus ReadOnlyEnlistment(long? virtual_clock, bool throw_on_error)
        {
            return NtSystemCalls.NtReadOnlyEnlistment(Handle, virtual_clock.ToLargeInteger()).ToNtException(throw_on_error);
        }

        /// <summary>
        /// Recover enlistment.
        /// </summary>
        /// <param name="virtual_clock">Optional virtual clock value.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public NtStatus RecoverEnlistment(long? virtual_clock, bool throw_on_error)
        {
            return NtSystemCalls.NtRecoverEnlistment(Handle, virtual_clock.ToLargeInteger()).ToNtException(throw_on_error);
        }

        /// <summary>
        /// Single phase reject enlistment.
        /// </summary>
        /// <param name="virtual_clock">Optional virtual clock value.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public NtStatus SinglePhaseReject(long? virtual_clock, bool throw_on_error)
        {
            return NtSystemCalls.NtSinglePhaseReject(Handle, virtual_clock.ToLargeInteger()).ToNtException(throw_on_error);
        }

        /// <summary>
        /// Commit complete enlistment.
        /// </summary>
        /// <param name="virtual_clock">Optional virtual clock value.</param>
        public void CommitComplete(long? virtual_clock)
        {
            CommitComplete(virtual_clock, true);
        }

        /// <summary>
        /// Commit enlistment.
        /// </summary>
        /// <param name="virtual_clock">Optional virtual clock value.</param>
        public void CommitEnlistment(long? virtual_clock)
        {
            CommitEnlistment(virtual_clock, true);
        }

        /// <summary>
        /// Preprepare complete enlistment.
        /// </summary>
        /// <param name="virtual_clock">Optional virtual clock value.</param>
        public void PrePrepareComplete(long? virtual_clock)
        {
            PrePrepareComplete(virtual_clock, true);
        }

        /// <summary>
        /// Preprepare enlistment.
        /// </summary>
        /// <param name="virtual_clock">Optional virtual clock value.</param>
        public void PrePrepareEnlistment(long? virtual_clock)
        {
            PrePrepareEnlistment(virtual_clock, true);
        }

        /// <summary>
        /// Prepare complete enlistment.
        /// </summary>
        /// <param name="virtual_clock">Optional virtual clock value.</param>
        public void PrepareComplete(long? virtual_clock)
        {
            PrepareComplete(virtual_clock, true);
        }

        /// <summary>
        /// Prepare enlistment.
        /// </summary>
        /// <param name="virtual_clock">Optional virtual clock value.</param>
        public void PrepareEnlistment(long? virtual_clock)
        {
            PrepareEnlistment(virtual_clock, true);
        }

        /// <summary>
        /// Rollback complete enlistment.
        /// </summary>
        /// <param name="virtual_clock">Optional virtual clock value.</param>
        public void RollbackComplete(long? virtual_clock)
        {
            RollbackComplete(virtual_clock, true);
        }

        /// <summary>
        /// Rollback enlistment.
        /// </summary>
        /// <param name="virtual_clock">Optional virtual clock value.</param>
        public void RollbackEnlistment(long? virtual_clock)
        {
            RollbackEnlistment(virtual_clock, true);
        }

        /// <summary>
        /// Read only enlistment.
        /// </summary>
        /// <param name="virtual_clock">Optional virtual clock value.</param>
        public void ReadOnlyEnlistment(long? virtual_clock)
        {
            ReadOnlyEnlistment(virtual_clock, true);
        }

        /// <summary>
        /// Recover enlistment.
        /// </summary>
        /// <param name="virtual_clock">Optional virtual clock value.</param>
        public void RecoverEnlistment(long? virtual_clock)
        {
            RecoverEnlistment(virtual_clock, true);
        }

        /// <summary>
        /// Single phase reject enlistment.
        /// </summary>
        /// <param name="virtual_clock">Optional virtual clock value.</param>
        public void SinglePhaseReject(long? virtual_clock)
        {
            SinglePhaseReject(virtual_clock, true);
        }

        /// <summary>
        /// Method to query information for this object type.
        /// </summary>
        /// <param name="info_class">The information class.</param>
        /// <param name="buffer">The buffer to return data in.</param>
        /// <param name="return_length">Return length from the query.</param>
        /// <returns>The NT status code for the query.</returns>
        public override NtStatus QueryInformation(EnlistmentInformationClass info_class, SafeBuffer buffer, out int return_length)
        {
            return NtSystemCalls.NtQueryInformationEnlistment(Handle, info_class, buffer, buffer.GetLength(), out return_length);
        }

        /// <summary>
        /// Method to set information for this object type.
        /// </summary>
        /// <param name="info_class">The information class.</param>
        /// <param name="buffer">The buffer to set data from.</param>
        /// <returns>The NT status code for the set.</returns>
        public override NtStatus SetInformation(EnlistmentInformationClass info_class, SafeBuffer buffer)
        {
            return NtSystemCalls.NtSetInformationEnlistment(Handle, info_class, buffer, buffer.GetLength());
        }

        #endregion

        #region Public Properties
        /// <summary>
        /// Get enlistment ID.
        /// </summary>
        public Guid EnlistmentId => QueryBasicInformation().EnlistmentId;
        /// <summary>
        /// Get associated transaction ID.
        /// </summary>
        public Guid TransactionId => QueryBasicInformation().TransactionId;
        /// <summary>
        /// Get resource manager ID.
        /// </summary>
        public Guid ResourceManagerId => QueryBasicInformation().ResourceManagerId;

        /// <summary>
        /// Get CRM enlistment ID.
        /// </summary>
        public Guid CrmEnlistmentId => QueryCrmInformation().CrmEnlistmentId;
        /// <summary>
        /// Get CRM transaction manager ID.
        /// </summary>
        public Guid CrmTransactionManagerId => QueryCrmInformation().CrmTransactionManagerId;
        /// <summary>
        /// Get CRM resource manager ID.
        /// </summary>
        public Guid CrmResourceManagerId => QueryCrmInformation().CrmResourceManagerId;

        /// <summary>
        /// Get or set recovery information.
        /// </summary>
        public byte[] RecoveryInformation
        {
            get
            {
                using (var buffer = QueryRawBuffer(EnlistmentInformationClass.EnlistmentRecoveryInformation))
                {
                    return buffer.ToArray();
                }
            }
            set
            {
                Set(EnlistmentInformationClass.EnlistmentRecoveryInformation, value);
            }
        }

        #endregion

        #region Private Properties
        private EnlistmentBasicInformation QueryBasicInformation()
        {
            return Query<EnlistmentBasicInformation>(EnlistmentInformationClass.EnlistmentBasicInformation);
        }

        private EnlistmentCrmInformation QueryCrmInformation()
        {
            return Query<EnlistmentCrmInformation>(EnlistmentInformationClass.EnlistmentCrmInformation);
        }
        #endregion
    }
}
