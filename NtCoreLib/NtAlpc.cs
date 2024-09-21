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

using NtCoreLib.Kernel.Alpc;
using NtCoreLib.Native.SafeBuffers;
using NtCoreLib.Native.SafeHandles;
using NtCoreLib.Security.Authorization;
using NtCoreLib.Security.Token;
using NtCoreLib.Utilities.Collections;
using NtCoreLib.Utilities.Token;
using System;
using System.Runtime.InteropServices;

namespace NtCoreLib;

/// <summary>
/// Class to represent an ALPC port.
/// </summary>
[NtType("ALPC Port")]
public class NtAlpc : NtObjectWithDuplicateAndInfo<NtAlpc, AlpcAccessRights, AlpcPortInformationClass, AlpcPortInformationClass>
{
    #region Constructors

    internal NtAlpc(SafeKernelObjectHandle handle) : base(handle)
    {
    }

    internal sealed class NtTypeFactoryImpl : NtTypeFactoryImplBase
    {
        public NtTypeFactoryImpl() : base(false)
        {
        }
    }

    #endregion

    #region Public Methods

    /// <summary>
    /// Disconnect this port.
    /// </summary>
    /// <param name="flags">Disconection flags.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The NT status code.</returns>
    public NtStatus Disconnect(AlpcDisconnectPortFlags flags, bool throw_on_error)
    {
        return NtSystemCalls.NtAlpcDisconnectPort(Handle, flags).ToNtException(throw_on_error);
    }

    /// <summary>
    /// Disconnect this port.
    /// </summary>
    /// <param name="flags">Disconection flags.</param>
    public void Disconnect(AlpcDisconnectPortFlags flags)
    {
        Disconnect(flags, true);
    }

    /// <summary>
    /// Disconnect this port.
    /// </summary>
    public void Disconnect()
    {
        Disconnect(AlpcDisconnectPortFlags.None);
    }

    /// <summary>
    /// Cancel a message based on a context attribute.
    /// </summary>
    /// <param name="flags">Cancellation flags.</param>
    /// <param name="context">The context attributes.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The NT status code.</returns>
    public NtStatus CancelMessage(AlpcCancelMessageFlags flags, AlpcContextMessageAttribute context, bool throw_on_error)
    {
        var attr = context.ToStruct();
        return NtSystemCalls.NtAlpcCancelMessage(Handle, flags, ref attr).ToNtException(throw_on_error);
    }

    /// <summary>
    /// Cancel a message based on a context attribute.
    /// </summary>
    /// <param name="flags">Cancellation flags.</param>
    /// <param name="context">The context attributes.</param>
    public void CancelMessage(AlpcCancelMessageFlags flags, AlpcContextMessageAttribute context)
    {
        CancelMessage(flags, context, true);
    }

    /// <summary>
    /// Cancel a message based on a context attribute.
    /// </summary>
    /// <param name="context">The context attributes.</param>
    public void CancelMessage(AlpcContextMessageAttribute context)
    {
        CancelMessage(AlpcCancelMessageFlags.None, context);
    }

    /// <summary>
    /// Send and receive messages on an ALPC port.
    /// </summary>
    /// <param name="flags">Send/Receive flags.</param>
    /// <param name="send_message">The message to send. Optional.</param>
    /// <param name="send_attributes">The attributes to send with the message. Optional.</param>
    /// <param name="receive_message">The message to receive. Optional.</param>
    /// <param name="receive_attributes">The attributes to receive with the message. Optional.</param>
    /// <param name="timeout">Time out for the send/receive.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The NT status code.</returns>
    /// <remarks>The attribute parameters will be repopulated with the attribute results.</remarks>
    public NtStatus SendReceive(AlpcMessageFlags flags, AlpcMessage send_message, AlpcSendMessageAttributes send_attributes,
        AlpcMessage receive_message, AlpcReceiveMessageAttributes receive_attributes, NtWaitTimeout timeout, bool throw_on_error)
    {
        using var list = new DisposableList();
        var send_msg = list.GetMessageBuffer(send_message);
        var recv_msg = list.GetMessageBuffer(receive_message);
        var send_attr = list.GetAttributesBuffer(send_attributes);
        var recv_attr = list.GetAttributesBuffer(receive_attributes);
        NtStatus status = NtSystemCalls.NtAlpcSendWaitReceivePort(Handle, flags, send_msg,
            send_attr, recv_msg, recv_msg.GetOptionalLength(), recv_attr, timeout?.Timeout).ToNtException(throw_on_error);
        if (status.IsSuccess())
        {
            receive_message?.FromSafeBuffer(recv_msg, this);
            receive_attributes?.FromSafeBuffer(recv_attr, this, receive_message);
            send_message?.FromSafeBuffer(send_msg, this);
        }
        return status;
    }

    /// <summary>
    /// Send and receive messages on an ALPC port.
    /// </summary>
    /// <param name="flags">Send/Receive flags.</param>
    /// <param name="send_message">The message to send. Optional.</param>
    /// <param name="send_attributes">The attributes to send with the message. Optional.</param>
    /// <param name="receive_message">The message to receive. Optional.</param>
    /// <param name="receive_attributes">The attributes to receive with the message. Optional.</param>
    /// <param name="timeout">Time out for the send/receive.</param>
    /// <returns>True if completed successfully, false if timed out.</returns>
    /// <exception cref="NtException">Thrown on error.</exception>
    public bool SendReceive(AlpcMessageFlags flags, AlpcMessage send_message, AlpcSendMessageAttributes send_attributes,
        AlpcMessage receive_message, AlpcReceiveMessageAttributes receive_attributes, NtWaitTimeout timeout)
    {
        return SendReceive(flags, send_message, send_attributes, receive_message, receive_attributes, timeout, true) != NtStatus.STATUS_TIMEOUT;
    }

    /// <summary>
    /// Send a message on an ALPC port.
    /// </summary>
    /// <param name="flags">Send flags.</param>
    /// <param name="send_message">The message to send. Optional.</param>
    /// <param name="send_attributes">The attributes to send with the message. Optional.</param>
    /// <param name="timeout">Time out for the send/receive.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The NT status code.</returns>
    /// <remarks>The attribute parameters will be repopulated with the attribute results.</remarks>
    public NtStatus Send(AlpcMessageFlags flags, AlpcMessage send_message, AlpcSendMessageAttributes send_attributes,
                        NtWaitTimeout timeout, bool throw_on_error)
    {
        return SendReceive(flags, send_message, send_attributes, null, null, timeout, throw_on_error);
    }

    /// <summary>
    /// Send a message on an ALPC port.
    /// </summary>
    /// <param name="flags">Send flags.</param>
    /// <param name="send_message">The message to send. Optional.</param>
    /// <param name="send_attributes">The attributes to send with the message. Optional.</param>
    /// <param name="timeout">Time out for the send/receive.</param>
    /// <remarks>The attribute parameters will be repopulated with the attribute results.</remarks>
    /// <returns>True if completed successfully, false if timed out.</returns>
    /// <exception cref="NtException">Thrown on error.</exception>
    public bool Send(AlpcMessageFlags flags, AlpcMessage send_message, AlpcSendMessageAttributes send_attributes,
                        NtWaitTimeout timeout)
    {
        return Send(flags, send_message, send_attributes, timeout, true) != NtStatus.STATUS_TIMEOUT;
    }

    /// <summary>
    /// Send a message on an ALPC port.
    /// </summary>
    /// <param name="flags">Send flags.</param>
    /// <param name="send_message">The message to send. Optional.</param>
    /// <remarks>The attribute parameters will be repopulated with the attribute results.</remarks>
    public void Send(AlpcMessageFlags flags, AlpcMessage send_message)
    {
        Send(flags, send_message, null, NtWaitTimeout.Infinite);
    }

    /// <summary>
    /// Receive a message on an ALPC port.
    /// </summary>
    /// <param name="flags">Receive flags.</param>
    /// <param name="receive_length">The maximum length to receive.</param>
    /// <param name="receive_attributes">The attributes to receive with the message. Optional.</param>
    /// <param name="timeout">Time out for the send/receive.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The received message.</returns>
    /// <remarks>The attribute parameters will be repopulated with the attribute results.</remarks>
    public NtResult<AlpcMessageRaw> Receive(AlpcMessageFlags flags, int receive_length,
        AlpcReceiveMessageAttributes receive_attributes, NtWaitTimeout timeout, bool throw_on_error)
    {
        var msg = new AlpcMessageRaw(receive_length);
        return SendReceive(flags, null, null, msg, receive_attributes,
            timeout, false).CreateResult(throw_on_error, s => s != NtStatus.STATUS_TIMEOUT ? msg : null);
    }

    /// <summary>
    /// Receive a message on an ALPC port.
    /// </summary>
    /// <param name="flags">Receive flags.</param>
    /// <param name="receive_length">The maximum length to receive.</param>
    /// <param name="receive_attributes">The attributes to receive with the message. Optional.</param>
    /// <param name="timeout">Time out for the send/receive.</param>
    /// <returns>The received message.</returns>
    /// <remarks>The attribute parameters will be repopulated with the attribute results.</remarks>
    public AlpcMessageRaw Receive(AlpcMessageFlags flags, int receive_length,
        AlpcReceiveMessageAttributes receive_attributes, NtWaitTimeout timeout)
    {
        return Receive(flags, receive_length, receive_attributes, timeout, true).Result;
    }

    /// <summary>
    /// Receive a message on an ALPC port.
    /// </summary>
    /// <param name="flags">Receive flags.</param>
    /// <param name="receive_length">The maximum length to receive.</param>
    /// <param name="receive_attributes">The attributes to receive with the message. Optional.</param>
    /// <returns>The received message.</returns>
    /// <remarks>The attribute parameters will be repopulated with the attribute results.</remarks>
    public AlpcMessageRaw Receive(AlpcMessageFlags flags, int receive_length,
        AlpcReceiveMessageAttributes receive_attributes)
    {
        return Receive(flags, receive_length, receive_attributes, NtWaitTimeout.Infinite);
    }

    /// <summary>
    /// Receive a message on an ALPC port.
    /// </summary>
    /// <param name="flags">Receive flags.</param>
    /// <param name="receive_length">The maximum length to receive.</param>
    /// <returns>The received message.</returns>
    /// <remarks>The attribute parameters will be repopulated with the attribute results.</remarks>
    public AlpcMessageRaw Receive(AlpcMessageFlags flags, int receive_length)
    {
        return Receive(flags, receive_length, null);
    }

    /// <summary>
    /// Receive a message on an ALPC port.
    /// </summary>
    /// <param name="flags">Receive flags.</param>
    /// <param name="receive_attributes">The attributes to receive with the message. Optional.</param>
    /// <param name="timeout">Time out for the send/receive.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The received message.</returns>
    /// <remarks>The attribute parameters will be repopulated with the attribute results.</remarks>
    /// <typeparam name="T">The type of structure to receive.</typeparam>
    public NtResult<AlpcMessageType<T>> Receive<T>(AlpcMessageFlags flags,
        AlpcReceiveMessageAttributes receive_attributes, NtWaitTimeout timeout,
        bool throw_on_error) where T : struct
    {
        var msg = new AlpcMessageType<T>();
        return SendReceive(flags, null, null, msg, receive_attributes,
            timeout, false).CreateResult(throw_on_error, () => msg);
    }

    /// <summary>
    /// Receive a message on an ALPC port.
    /// </summary>
    /// <param name="flags">Receive flags.</param>
    /// <param name="receive_attributes">The attributes to receive with the message. Optional.</param>
    /// <param name="timeout">Time out for the send/receive.</param>
    /// <remarks>The attribute parameters will be repopulated with the attribute results.</remarks>
    /// <typeparam name="T">The type of structure to receive.</typeparam>
    public AlpcMessageType<T> Receive<T>(AlpcMessageFlags flags,
        AlpcReceiveMessageAttributes receive_attributes, NtWaitTimeout timeout) where T : struct
    {
        return Receive<T>(flags, receive_attributes, timeout, true).Result;
    }

    /// <summary>
    /// Receive a message on an ALPC port.
    /// </summary>
    /// <param name="flags">Receive flags.</param>
    /// <param name="receive_attributes">The attributes to receive with the message. Optional.</param>
    /// <remarks>The attribute parameters will be repopulated with the attribute results.</remarks>
    /// <typeparam name="T">The type of structure to receive.</typeparam>
    public AlpcMessageType<T> Receive<T>(AlpcMessageFlags flags,
        AlpcReceiveMessageAttributes receive_attributes) where T : struct
    {
        return Receive<T>(flags, receive_attributes, NtWaitTimeout.Infinite);
    }

    /// <summary>
    /// Receive a message on an ALPC port.
    /// </summary>
    /// <param name="flags">Receive flags.</param>
    /// <typeparam name="T">The type of structure to receive.</typeparam>
    public AlpcMessageType<T> Receive<T>(AlpcMessageFlags flags) where T : struct
    {
        return Receive<T>(flags, null);
    }

    /// <summary>
    /// Impersonate client of port for a message.
    /// </summary>
    /// <param name="message">The message send by the client.</param>
    /// <param name="flags">Impersonation flags.</param>
    /// <param name="required_impersonation_level">Required impersonation level. Need to set RequiredImpersonationLevel flag as well.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>Thread impersonation context.</returns>
    public NtResult<ThreadImpersonationContext> ImpersonateClientOfPort(AlpcMessage message,
        AlpcImpersonationClientOfPortFlags flags, SecurityImpersonationLevel required_impersonation_level,
        bool throw_on_error)
    {
        int full_flags = (int)flags | (int)required_impersonation_level << 2;
        return NtSystemCalls.NtAlpcImpersonateClientOfPort(Handle, message.Header, (AlpcImpersonationClientOfPortFlags)full_flags)
            .CreateResult(throw_on_error, () => new ThreadImpersonationContext());
    }

    /// <summary>
    /// Impersonate client of port for a message.
    /// </summary>
    /// <param name="message">The message send by the client.</param>
    /// <param name="flags">Impersonation flags.</param>
    /// <param name="required_impersonation_level">Required impersonation level. Need to set RequiredImpersonationLevel flag as well.</param>
    /// <returns>Thread impersonation context.</returns>
    public ThreadImpersonationContext ImpersonateClientOfPort(AlpcMessage message,
        AlpcImpersonationClientOfPortFlags flags, SecurityImpersonationLevel required_impersonation_level)
    {
        return ImpersonateClientOfPort(message, flags, required_impersonation_level, true).Result;
    }

    /// <summary>
    /// Impersonate client of port for a message.
    /// </summary>
    /// <param name="message">The message send by the client.</param>
    /// <returns>Thread impersonation context.</returns>
    public ThreadImpersonationContext ImpersonateClientOfPort(AlpcMessage message)
    {
        return ImpersonateClientOfPort(message, AlpcImpersonationClientOfPortFlags.None, SecurityImpersonationLevel.Anonymous);
    }

    /// <summary>
    /// Impersonate client container of port for a message.
    /// </summary>
    /// <param name="message">The message send by the client.</param>
    /// <param name="flags">Impersonation flags.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>Thread impersonation context.</returns>
    public NtResult<ThreadImpersonationContext> ImpersonateClientContainerOfPort(AlpcMessage message,
        AlpcImpersonateClientContainerOfPortFlags flags, bool throw_on_error)
    {
        return NtSystemCalls.NtAlpcImpersonateClientContainerOfPort(Handle, message.Header, flags)
            .CreateResult(throw_on_error, () => new ThreadImpersonationContext());
    }

    /// <summary>
    /// Impersonate client container of port for a message.
    /// </summary>
    /// <param name="message">The message send by the client.</param>
    /// <param name="flags">Impersonation flags.</param>
    /// <returns>Thread impersonation context.</returns>
    public ThreadImpersonationContext ImpersonateClientContainerOfPort(AlpcMessage message,
        AlpcImpersonateClientContainerOfPortFlags flags)
    {
        return ImpersonateClientContainerOfPort(message, flags, true).Result;
    }

    /// <summary>
    /// Impersonate client container of port for a message.
    /// </summary>
    /// <param name="message">The message send by the client.</param>
    /// <returns>Thread impersonation context.</returns>
    public ThreadImpersonationContext ImpersonateClientContainerOfPort(AlpcMessage message)
    {
        return ImpersonateClientContainerOfPort(message, AlpcImpersonateClientContainerOfPortFlags.None);
    }

    /// <summary>
    /// Open the process of the message sender.
    /// </summary>
    /// <param name="message">The sent message.</param>
    /// <param name="flags">Optional flags. Currently none defined.</param>
    /// <param name="desired_access">The desired access for the process.</param>
    /// <param name="object_attributes">Optional object attributes.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The opened process object.</returns>
    public NtResult<NtProcess> OpenSenderProcess(AlpcMessage message, AlpcOpenSenderProcessFlags flags, ProcessAccessRights desired_access, ObjectAttributes object_attributes, bool throw_on_error)
    {
        return NtSystemCalls.NtAlpcOpenSenderProcess(out SafeKernelObjectHandle handle, Handle,
            message.Header, flags, desired_access, object_attributes)
            .CreateResult(throw_on_error, () => new NtProcess(handle));
    }

    /// <summary>
    /// Open the process of the message sender.
    /// </summary>
    /// <param name="message">The sent message.</param>
    /// <param name="flags">Optional flags. Currently none defined.</param>
    /// <param name="desired_access">The desired access for the process.</param>
    /// <param name="object_attributes">Optional object attributes.</param>
    /// <returns>The opened process object.</returns>
    public NtProcess OpenSenderProcess(AlpcMessage message, AlpcOpenSenderProcessFlags flags, ProcessAccessRights desired_access, ObjectAttributes object_attributes)
    {
        return OpenSenderProcess(message, flags, desired_access, object_attributes, true).Result;
    }

    /// <summary>
    /// Open the process of the message sender.
    /// </summary>
    /// <param name="message">The sent message.</param>
    /// <param name="desired_access">The desired access for the process.</param>
    /// <returns>The opened process object.</returns>
    public NtProcess OpenSenderProcess(AlpcMessage message, ProcessAccessRights desired_access)
    {
        return OpenSenderProcess(message, AlpcOpenSenderProcessFlags.None,
            desired_access, new ObjectAttributes());
    }

    /// <summary>
    /// Open the process of the message sender with maximum privileges.
    /// </summary>
    /// <param name="message">The sent message.</param>
    /// <returns>The opened process object.</returns>
    public NtProcess OpenSenderProcess(AlpcMessage message)
    {
        return OpenSenderProcess(message, ProcessAccessRights.MaximumAllowed);
    }

    /// <summary>
    /// Open the thread of the message sender.
    /// </summary>
    /// <param name="message">The sent message.</param>
    /// <param name="flags">Optional flags. Currently none defined.</param>
    /// <param name="desired_access">The desired access for the thread.</param>
    /// <param name="object_attributes">Optional object attributes.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The opened thread object.</returns>
    public NtResult<NtThread> OpenSenderThread(AlpcMessage message, AlpcOpenSenderThreadFlags flags,
        ThreadAccessRights desired_access, ObjectAttributes object_attributes, bool throw_on_error)
    {
        return NtSystemCalls.NtAlpcOpenSenderThread(out SafeKernelObjectHandle handle, Handle,
            message.Header, flags, desired_access, object_attributes)
            .CreateResult(throw_on_error, () => new NtThread(handle));
    }

    /// <summary>
    /// Open the thread of the message sender.
    /// </summary>
    /// <param name="message">The sent message.</param>
    /// <param name="flags">Optional flags. Currently none defined.</param>
    /// <param name="desired_access">The desired access for the thread.</param>
    /// <param name="object_attributes">Optional object attributes.</param>
    /// <returns>The opened thread object.</returns>
    public NtThread OpenSenderThread(AlpcMessage message, AlpcOpenSenderThreadFlags flags,
        ThreadAccessRights desired_access, ObjectAttributes object_attributes)
    {
        return OpenSenderThread(message, flags, desired_access, object_attributes, true).Result;
    }

    /// <summary>
    /// Open the thread of the message sender.
    /// </summary>
    /// <param name="message">The sent message.</param>
    /// <param name="desired_access">The desired access for the thread.</param>
    /// <returns>The opened thread object.</returns>
    public NtThread OpenSenderThread(AlpcMessage message, ThreadAccessRights desired_access)
    {
        return OpenSenderThread(message, AlpcOpenSenderThreadFlags.None,
            desired_access, new ObjectAttributes());
    }

    /// <summary>
    /// Open the thread of the message sender with maximum privileges.
    /// </summary>
    /// <param name="message">The sent message.</param>
    /// <returns>The opened thread object.</returns>
    public NtThread OpenSenderThread(AlpcMessage message)
    {
        return OpenSenderThread(message, ThreadAccessRights.MaximumAllowed);
    }

    /// <summary>
    /// Associate an IO completion port with this ALPC port.
    /// </summary>
    /// <param name="io_completion">The IO completion object.</param>
    /// <param name="completion_key">Optional completion key.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The NT status code.</returns>
    public NtStatus AssociateCompletionPort(NtIoCompletion io_completion, IntPtr completion_key, bool throw_on_error)
    {
        AlpcPortAssociateCompletionPort info = new()
        {
            CompletionPort = io_completion.Handle.DangerousGetHandle(),
            CompletionKey = completion_key
        };
        return Set(AlpcPortInformationClass.AlpcAssociateCompletionPortInformation, info, throw_on_error);
    }

    /// <summary>
    /// Associate an IO completion port with this ALPC port.
    /// </summary>
    /// <param name="io_completion">The IO completion object.</param>
    /// <param name="completion_key">Optional completion key.</param>
    /// <returns>The NT status code.</returns>
    public void AssociateCompletionPort(NtIoCompletion io_completion, IntPtr completion_key)
    {
        AssociateCompletionPort(io_completion, completion_key, true);
    }

    /// <summary>
    /// Check if the current SID matches the connected SID.
    /// </summary>
    /// <param name="sid">The SID to compare.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>True if the connected SID matches the specified SID.</returns>
    public NtResult<bool> IsConnectedSid(Sid sid, bool throw_on_error)
    {
        using var buffer = sid.ToArray().ToBuffer();
        NtStatus status = QueryInformation(AlpcPortInformationClass.AlpcConnectedSIDInformation, buffer, out int return_length);
        if (status == NtStatus.STATUS_SERVER_SID_MISMATCH)
        {
            return false.CreateResult();
        }
        return status.CreateResult(throw_on_error, () => true);
    }

    /// <summary>
    /// Check if the current SID matches the connected SID.
    /// </summary>
    /// <param name="sid">The SID to compare.</param>
    /// <returns>True if the connected SID matches the specified SID.</returns>
    public bool IsConnectedSid(Sid sid)
    {
        return IsConnectedSid(sid, true).Result;
    }

    /// <summary>
    /// Create a new port section.
    /// </summary>
    /// <param name="flags">Flags for the port section.</param>
    /// <param name="section">Optional backing section.</param>
    /// <param name="section_size">Size of the section to create.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The created port section.</returns>
    public NtResult<AlpcPortSection> CreatePortSection(AlpcCreatePortSectionFlags flags, NtSection section, long section_size, bool throw_on_error)
    {
        return NtSystemCalls.NtAlpcCreatePortSection(Handle, flags, section.GetHandle(), new IntPtr(section_size),
            out AlpcHandle handle, out IntPtr actual_section_size).CreateResult(throw_on_error, ()
                => new AlpcPortSection(handle, new IntPtr(section_size), actual_section_size, this));
    }

    /// <summary>
    /// Create a new port section.
    /// </summary>
    /// <param name="flags">Flags for the port section.</param>
    /// <param name="section">Optional backing section.</param>
    /// <param name="section_size">Size of the section to create.</param>
    /// <returns>The created port section.</returns>
    public AlpcPortSection CreatePortSection(AlpcCreatePortSectionFlags flags, NtSection section, long section_size)
    {
        return CreatePortSection(flags, section, section_size, true).Result;
    }

    /// <summary>
    /// Create a new port section.
    /// </summary>
    /// <param name="flags">Flags for the port section.</param>
    /// <param name="section_size">Size of the section to create.</param>
    /// <returns>The created port section.</returns>
    public AlpcPortSection CreatePortSection(AlpcCreatePortSectionFlags flags, long section_size)
    {
        return CreatePortSection(flags, null, section_size);
    }

    /// <summary>
    /// Create a new port section.
    /// </summary>
    /// <param name="section_size">Size of the section to create.</param>
    /// <returns>The created port section.</returns>
    public AlpcPortSection CreatePortSection(long section_size)
    {
        return CreatePortSection(AlpcCreatePortSectionFlags.None, section_size);
    }

    /// <summary>
    /// Get a handle entry for a message.
    /// </summary>
    /// <param name="index">The handle index to get.</param>
    /// <param name="message">The associated message.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The ALPC handle entry.</returns>
    public NtResult<AlpcHandleMessageAttributeEntry> GetHandleInformation(AlpcMessage message, int index, bool throw_on_error)
    {
        return message.Query(this, AlpcMessageInformationClass.AlpcMessageHandleInformation,
            new AlpcMessageHandleInformation() { Index = index }, throw_on_error).Map(s => new AlpcHandleMessageAttributeEntry(s));
    }

    /// <summary>
    /// Get a handle entry for a message.
    /// </summary>
    /// <param name="index">The handle index to get.</param>
    /// <param name="message">The associated message.</param>
    /// <returns>The ALPC handle entry.</returns>
    public AlpcHandleMessageAttributeEntry GetHandleInformation(AlpcMessage message, int index)
    {
        return GetHandleInformation(message, index, true).Result;
    }

    /// <summary>
    /// Create a security context.
    /// </summary>
    /// <param name="flags">Flags for the creation.</param>
    /// <param name="security_quality_of_service">Security quality of service.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The created security context.</returns>
    public NtResult<SafeAlpcSecurityContextHandle> CreateSecurityContext(AlpcCreateSecurityContextFlags flags,
        SecurityQualityOfService security_quality_of_service, bool throw_on_error)
    {
        using var list = new DisposableList();
        var sqos = security_quality_of_service == null ? SafeHGlobalBuffer.Null : list.AddResource(security_quality_of_service.ToBuffer());
        AlpcSecurityAttr attr = new()
        {
            QoS = sqos.DangerousGetHandle()
        };
        return NtSystemCalls.NtAlpcCreateSecurityContext(Handle, flags, ref attr)
            .CreateResult(throw_on_error, ()
                    => new SafeAlpcSecurityContextHandle(attr.ContextHandle,
                    true, this, AlpcSecurityAttrFlags.None, security_quality_of_service));
    }

    /// <summary>
    /// Create a security context.
    /// </summary>
    /// <param name="flags">Flags for the creation.</param>
    /// <param name="security_quality_of_service">Security quality of service.</param>
    /// <returns>The created security context.</returns>
    public SafeAlpcSecurityContextHandle CreateSecurityContext(AlpcCreateSecurityContextFlags flags,
        SecurityQualityOfService security_quality_of_service)
    {
        return CreateSecurityContext(flags, security_quality_of_service, true).Result;
    }

    /// <summary>
    /// Create a security context.
    /// </summary>
    /// <param name="security_quality_of_service">Security quality of service.</param>
    /// <returns>The created security context.</returns>
    public SafeAlpcSecurityContextHandle CreateSecurityContext(SecurityQualityOfService security_quality_of_service)
    {
        return CreateSecurityContext(AlpcCreateSecurityContextFlags.None, security_quality_of_service);
    }

    /// <summary>
    /// Create a security context.
    /// </summary>
    /// <returns>The created security context.</returns>
    public SafeAlpcSecurityContextHandle CreateSecurityContext()
    {
        return CreateSecurityContext(new SecurityQualityOfService(SecurityImpersonationLevel.Impersonation, SecurityContextTrackingMode.Static, false));
    }

    /// <summary>
    /// Set port attribute flags.
    /// </summary>
    /// <param name="flags">The flags to set.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The NT status code.</returns>
    public NtStatus SetPortAttributeFlags(AlpcPortAttributeFlags flags, bool throw_on_error)
    {
        return Set(AlpcPortInformationClass.AlpcPortInformation, new AlpcPortAttributes() { Flags = flags }, throw_on_error);
    }

    /// <summary>
    /// Method to query information for this object type.
    /// </summary>
    /// <param name="info_class">The information class.</param>
    /// <param name="buffer">The buffer to return data in.</param>
    /// <param name="return_length">Return length from the query.</param>
    /// <returns>The NT status code for the query.</returns>
    public override NtStatus QueryInformation(AlpcPortInformationClass info_class, SafeBuffer buffer, out int return_length)
    {
        return NtSystemCalls.NtAlpcQueryInformation(Handle, info_class, buffer, (int)buffer.ByteLength, out return_length);
    }

    /// <summary>
    /// Method to set information for this object type.
    /// </summary>
    /// <param name="info_class">The information class.</param>
    /// <param name="buffer">The buffer to set data from.</param>
    /// <returns>The NT status code for the set.</returns>
    public override NtStatus SetInformation(AlpcPortInformationClass info_class, SafeBuffer buffer)
    {
        return NtSystemCalls.NtAlpcSetInformation(Handle, info_class, buffer, (int)buffer.ByteLength);
    }

    #endregion

    #region Public Properties

    /// <summary>
    /// Port flags.
    /// </summary>
    public AlpcPortAttributeFlags Flags
    {
        get => Query<AlpcBasicInformation>(AlpcPortInformationClass.AlpcBasicInformation).Flags;
        set => SetPortAttributeFlags(value, true);
    }

    /// <summary>
    /// Port sequence number.
    /// </summary>
    public int SequenceNumber => Query<AlpcBasicInformation>(AlpcPortInformationClass.AlpcBasicInformation).SequenceNo;

    /// <summary>
    /// Port context.
    /// </summary>
    public long PortContext => Query<AlpcBasicInformation>(AlpcPortInformationClass.AlpcBasicInformation).PortContext.ToInt64();



    #endregion
}
