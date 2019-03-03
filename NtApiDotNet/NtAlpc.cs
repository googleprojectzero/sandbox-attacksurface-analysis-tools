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

using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace NtApiDotNet
{
    /// <summary>
    /// Class to represent an ALPC port.
    /// </summary>
    [NtType("ALPC Port")]
    public class NtAlpc : NtObjectWithDuplicateAndInfo<NtAlpc, AlpcAccessRights, AlpcPortInformationClass, AlpcPortInformationClass>
    {
        #region Constructors

        internal NtAlpc(SafeKernelObjectHandle handle, bool connected) : base(handle)
        {
            _connected = connected;
        }

        internal NtAlpc(SafeKernelObjectHandle handle) : this(handle, false)
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
        public NtStatus SendReceive(AlpcMessageFlags flags, AlpcMessage send_message, AlpcMessageAttributeSet send_attributes,
            AlpcMessage receive_message, AlpcMessageAttributeSet receive_attributes, NtWaitTimeout timeout, bool throw_on_error)
        {
            using (var list = new DisposableList())
            {
                var send_msg = send_message == null ? SafeAlpcPortMessageBuffer.Null : send_message.Buffer;
                var recv_msg = receive_message == null ? SafeAlpcPortMessageBuffer.Null : receive_message.Buffer;
                var recv_length = receive_message == null ? null : new OptionalLength(receive_message.Buffer.Length);
                var send_attr = send_attributes.GetAttributes();
                var recv_attr = receive_attributes.GetAttributes();
                NtStatus status = NtSystemCalls.NtAlpcSendWaitReceivePort(Handle, flags, send_msg,
                    send_attr, recv_msg, recv_length, recv_attr, timeout?.Timeout).ToNtException(throw_on_error);
                if (status.IsSuccess())
                {
                    receive_attributes?.Rebuild();
                }
                return status;
            }
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
        public void SendReceive(AlpcMessageFlags flags, AlpcMessage send_message, AlpcMessageAttributeSet send_attributes,
            AlpcMessage receive_message, AlpcMessageAttributeSet receive_attributes, NtWaitTimeout timeout)
        {
            SendReceive(flags, send_message, send_attributes, receive_message, receive_attributes, timeout, true);
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
        public NtStatus Send(AlpcMessageFlags flags, AlpcMessage send_message, AlpcMessageAttributeSet send_attributes,
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
        public void Send(AlpcMessageFlags flags, AlpcMessage send_message, AlpcMessageAttributeSet send_attributes,
                            NtWaitTimeout timeout)
        {
            Send(flags, send_message, send_attributes, timeout, true);
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
        public NtResult<AlpcMessage> Receive(AlpcMessageFlags flags, int receive_length,
            AlpcMessageAttributeSet receive_attributes, NtWaitTimeout timeout, bool throw_on_error)
        {
            using (var msg = AlpcMessage.Create(receive_length, false))
            {
                return SendReceive(flags, null, null, msg, receive_attributes, 
                    timeout, false).CreateResult(throw_on_error, () => msg.Detach());
            }
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
        public AlpcMessage Receive(AlpcMessageFlags flags, int receive_length,
            AlpcMessageAttributeSet receive_attributes, NtWaitTimeout timeout)
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
        public AlpcMessage Receive(AlpcMessageFlags flags, int receive_length,
            AlpcMessageAttributeSet receive_attributes)
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
        public AlpcMessage Receive(AlpcMessageFlags flags, int receive_length)
        {
            return Receive(flags, receive_length, null);
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
            AlpcImpersonationFlags flags, SecurityImpersonationLevel required_impersonation_level,
            bool throw_on_error)
        {
            int full_flags = (int)flags | (((int)required_impersonation_level) << 2);
            return NtSystemCalls.NtAlpcImpersonateClientOfPort(Handle, message.GetMessage(), (AlpcImpersonationFlags)full_flags)
                .CreateResult(throw_on_error, () => new ThreadImpersonationContext(NtThread.Current.Duplicate()));
        }

        /// <summary>
        /// Impersonate client of port for a message.
        /// </summary>
        /// <param name="message">The message send by the client.</param>
        /// <param name="flags">Impersonation flags.</param>
        /// <param name="required_impersonation_level">Required impersonation level. Need to set RequiredImpersonationLevel flag as well.</param>
        /// <returns>Thread impersonation context.</returns>
        public ThreadImpersonationContext ImpersonateClientOfPort(AlpcMessage message,
            AlpcImpersonationFlags flags, SecurityImpersonationLevel required_impersonation_level)
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
            return ImpersonateClientOfPort(message, AlpcImpersonationFlags.None, SecurityImpersonationLevel.Anonymous);
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

        #region Private Members

        private readonly bool _connected;

        #endregion
    }

    /// <summary>
    /// Class to represent an ALPC client port.
    /// </summary>
    public class NtAlpcClient : NtAlpc
    {
        #region Private Members

        private static NtResult<NtAlpcClient> ConnectInternal(
            string port_name,
            ObjectAttributes port_object_attributes,
            ObjectAttributes object_attributes,
            AlpcPortAttributes port_attributes,
            AlpcMessageFlags flags,
            Sid required_server_sid,
            SecurityDescriptor server_security_requirements,
            AlpcMessage connection_message,
            AlpcMessageAttributeSet out_message_attributes,
            AlpcMessageAttributeSet in_message_attributes,
            NtWaitTimeout timeout,
            bool throw_on_error)
        {
            using (var list = new DisposableList())
            {
                var sid = list.AddSid(required_server_sid);
                var sd = list.AddSecurityDescriptor(server_security_requirements);
                var message = connection_message == null ? SafeAlpcPortMessageBuffer.Null :
                                    connection_message.Buffer;
                var message_length = connection_message == null ? null : new OptionalLength(connection_message.TotalLength);
                var out_attr = out_message_attributes.GetAttributes();
                var in_attr = in_message_attributes.GetAttributes();

                SafeKernelObjectHandle handle;
                NtStatus status;

                if (port_object_attributes != null)
                {
                    status = NtSystemCalls.NtAlpcConnectPortEx(out handle,
                        port_object_attributes, object_attributes, port_attributes,
                        flags, sd, message, message_length, out_attr, in_attr, timeout?.Timeout);
                }
                else
                {
                    status = NtSystemCalls.NtAlpcConnectPort(out handle,
                        new UnicodeString(port_name), object_attributes, port_attributes,
                        flags, sid, message, message_length, out_attr, in_attr, timeout?.Timeout);
                }
                return status.CreateResult(throw_on_error, () =>
                {
                    in_message_attributes?.Rebuild();
                    return new NtAlpcClient(handle);
                });
            }
        }
        #endregion

        #region Constructors

        internal NtAlpcClient(SafeKernelObjectHandle handle)
    :       base(handle, true)
        {
        }

        #endregion

        #region Static Methods

        /// <summary>
        /// Connect to an ALPC port.
        /// </summary>
        /// <param name="port_name">The path to the port.</param>
        /// <param name="object_attributes">Object attributes for the handle. Optional.</param>
        /// <param name="port_attributes">Attributes for the port. Optional.</param>
        /// <param name="flags">Send flags for the initial connection message.</param>
        /// <param name="required_server_sid">Required SID for the server.</param>
        /// <param name="connection_message">Initial connection message.</param>
        /// <param name="out_message_attributes">Outbound message attributes.</param>
        /// <param name="in_message_attributes">Inbound message atributes.</param>
        /// <param name="timeout">Connect timeout.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The connected ALPC port.</returns>
        public static NtResult<NtAlpcClient> Connect(
            string port_name,
            ObjectAttributes object_attributes,
            AlpcPortAttributes port_attributes,
            AlpcMessageFlags flags,
            Sid required_server_sid,
            AlpcMessage connection_message,
            AlpcMessageAttributeSet out_message_attributes,
            AlpcMessageAttributeSet in_message_attributes,
            NtWaitTimeout timeout,
            bool throw_on_error)
        {
            return ConnectInternal(port_name, null, object_attributes, port_attributes,
                flags, required_server_sid, null, connection_message, out_message_attributes, in_message_attributes,
                timeout, throw_on_error);
        }

        /// <summary>
        /// Connect to an ALPC port.
        /// </summary>
        /// <param name="port_name">The path to the port.</param>
        /// <param name="object_attributes">Object attributes for the handle. Optional.</param>
        /// <param name="port_attributes">Attributes for the port. Optional.</param>
        /// <param name="flags">Send flags for the initial connection message.</param>
        /// <param name="required_server_sid">Required SID for the server.</param>
        /// <param name="connection_message">Initial connection message.</param>
        /// <param name="out_message_attributes">Outbound message attributes.</param>
        /// <param name="in_message_attributes">Inbound message atributes.</param>
        /// <param name="timeout">Connect timeout.</param>
        /// <returns>The connected ALPC port.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static NtAlpcClient Connect(
            string port_name,
            ObjectAttributes object_attributes,
            AlpcPortAttributes port_attributes,
            AlpcMessageFlags flags,
            Sid required_server_sid,
            AlpcMessage connection_message,
            AlpcMessageAttributeSet out_message_attributes,
            AlpcMessageAttributeSet in_message_attributes,
            NtWaitTimeout timeout)
        {
            return Connect(port_name, object_attributes, port_attributes, flags, required_server_sid,
                connection_message, out_message_attributes, in_message_attributes, timeout, true).Result;
        }

        /// <summary>
        /// Connect to an ALPC port.
        /// </summary>
        /// <param name="port_name">The name of the port to connect to.</param>
        /// <param name="port_attributes">Attributes for the port.</param>
        /// <returns>The connected ALPC port object.</returns>
        public static NtAlpcClient Connect(string port_name, AlpcPortAttributes port_attributes = null)
        {
            return Connect(port_name, null, port_attributes, AlpcMessageFlags.None, null, null,
                    null, null, NtWaitTimeout.Infinite);
        }

        /// <summary>
        /// Connect to an ALPC port.
        /// </summary>
        /// <param name="port_object_attributes">Object attribute for the port name.</param>
        /// <param name="object_attributes">Object attributes for the handle. Optional.</param>
        /// <param name="port_attributes">Attributes for the port. Optional.</param>
        /// <param name="flags">Send flags for the initial connection message.</param>
        /// <param name="server_security_requirements">Required security descriptor for the server.</param>
        /// <param name="connection_message">Initial connection message.</param>
        /// <param name="out_message_attributes">Outbound message attributes.</param>
        /// <param name="in_message_attributes">Inbound message atributes.</param>
        /// <param name="timeout">Connect timeout.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The connected ALPC port.</returns>
        /// <remarks>Only available on Windows 8+.</remarks>
        [SupportedVersion(SupportedVersion.Windows8)]
        public static NtResult<NtAlpcClient> Connect(
            ObjectAttributes port_object_attributes,
            ObjectAttributes object_attributes,
            AlpcPortAttributes port_attributes,
            AlpcMessageFlags flags,
            SecurityDescriptor server_security_requirements,
            AlpcMessage connection_message,
            AlpcMessageAttributeSet out_message_attributes,
            AlpcMessageAttributeSet in_message_attributes,
            NtWaitTimeout timeout,
            bool throw_on_error)
        {
            return ConnectInternal(null, port_object_attributes, object_attributes, port_attributes, flags, 
                null, server_security_requirements,
                connection_message, out_message_attributes, in_message_attributes, timeout, throw_on_error);
        }

        /// <summary>
        /// Connect to an ALPC port.
        /// </summary>
        /// <param name="port_object_attributes">Object attribute for the port name.</param>
        /// <param name="object_attributes">Object attributes for the handle. Optional.</param>
        /// <param name="port_attributes">Attributes for the port. Optional.</param>
        /// <param name="flags">Send flags for the initial connection message.</param>
        /// <param name="server_security_requirements">Required security descriptor for the server.</param>
        /// <param name="connection_message">Initial connection message.</param>
        /// <param name="out_message_attributes">Outbound message attributes.</param>
        /// <param name="in_message_attributes">Inbound message atributes.</param>
        /// <param name="timeout">Connect timeout.</param>
        /// <returns>The connected ALPC port.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        [SupportedVersion(SupportedVersion.Windows8)]
        public static NtAlpcClient Connect(
            ObjectAttributes port_object_attributes,
            ObjectAttributes object_attributes,
            AlpcPortAttributes port_attributes,
            AlpcMessageFlags flags,
            SecurityDescriptor server_security_requirements,
            AlpcMessage connection_message,
            AlpcMessageAttributeSet out_message_attributes,
            AlpcMessageAttributeSet in_message_attributes,
            NtWaitTimeout timeout)
        {
            return Connect(port_object_attributes, object_attributes, port_attributes, flags, server_security_requirements,
                connection_message, out_message_attributes, in_message_attributes, timeout, true).Result;
        }

        /// <summary>
        /// Connect to an ALPC port.
        /// </summary>
        /// <param name="port_object_attributes">Object attribute for the port name.</param>
        /// <param name="port_attributes">Attributes for the port.</param>
        /// <returns>The connected ALPC port object.</returns>
        public static NtAlpcClient Connect(ObjectAttributes port_object_attributes, AlpcPortAttributes port_attributes = null)
        {
            return Connect(port_object_attributes, null, port_attributes, AlpcMessageFlags.None, null, null,
                    null, null, NtWaitTimeout.Infinite);
        }

        #endregion

        #region Protected Members

        /// <summary>
        /// Dispose port.
        /// </summary>
        /// <param name="disposing">True when disposing, false if finalizing</param>
        protected override void Dispose(bool disposing)
        {
            Disconnect(AlpcDisconnectPortFlags.None, false);
            base.Dispose(disposing);
        }

        #endregion
    }

    /// <summary>
    /// Class to represent an ALPC server port.
    /// </summary>
    public class NtAlpcServer : NtAlpc
    {
        internal NtAlpcServer(SafeKernelObjectHandle handle) 
            : base(handle, false)
        {
        }

        /// <summary>
        /// Create an ALPC port.
        /// </summary>
        /// <param name="object_attributes">The object attributes for the port.</param>
        /// <param name="port_attributes">The attributes for the port.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The created object.</returns>
        public static NtResult<NtAlpcServer> Create(ObjectAttributes object_attributes, 
            AlpcPortAttributes port_attributes, bool throw_on_error)
        {
            return NtSystemCalls.NtAlpcCreatePort(out SafeKernelObjectHandle handle, 
                object_attributes, port_attributes).CreateResult(throw_on_error, () => new NtAlpcServer(handle));
        }

        /// <summary>
        /// Create an ALPC port.
        /// </summary>
        /// <param name="object_attributes">The object attributes for the port.</param>
        /// <param name="port_attributes">The attributes for the port.</param>
        /// <returns>The created object.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static NtAlpcServer Create(ObjectAttributes object_attributes, AlpcPortAttributes port_attributes)
        {
            return Create(object_attributes, port_attributes, true).Result;
        }

        /// <summary>
        /// Create an ALPC port.
        /// </summary>
        /// <param name="port_name">The name of the port to create.</param>
        /// <param name="port_attributes">The attributes for the port.</param>
        /// <returns>The created object.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static NtAlpcServer Create(string port_name = null, AlpcPortAttributes port_attributes = null)
        {
            using (var obj_attr = new ObjectAttributes(port_name, AttributeFlags.CaseInsensitive))
            {
                return Create(obj_attr, port_attributes);
            }
        }

        /// <summary>
        /// Accept a new connection on a port.
        /// </summary>
        /// <param name="flags">The message send flags.</param>
        /// <param name="object_attributes">Object attributes. Optional.</param>
        /// <param name="port_attributes">The attributes for the port.</param>
        /// <param name="port_context">Port context. Optional.</param>
        /// <param name="connection_request">Connect request message.</param>
        /// <param name="connection_message_attributes">Connect request attributes.</param>
        /// <param name="accept_connection">True to accept the connection.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The accepted port.</returns>
        public NtResult<NtAlpcServer> AcceptConnectPort(
            AlpcMessageFlags flags,
            ObjectAttributes object_attributes,
            AlpcPortAttributes port_attributes,
            IntPtr port_context,
            AlpcMessage connection_request,
            AlpcMessageAttributeSet connection_message_attributes,
            bool accept_connection,
            bool throw_on_error)
        {
            using (var list = new DisposableList())
            {
                return NtSystemCalls.NtAlpcAcceptConnectPort(out SafeKernelObjectHandle handle,
                    Handle, flags, object_attributes, port_attributes, port_context, connection_request.GetMessage(),
                    connection_message_attributes.GetAttributes(), accept_connection)
                    .CreateResult(throw_on_error, () => new NtAlpcServer(handle));
            }
        }

        /// <summary>
        /// Accept a new connection on a port.
        /// </summary>
        /// <param name="flags">The message send flags.</param>
        /// <param name="object_attributes">Object attributes. Optional.</param>
        /// <param name="port_attributes">The attributes for the port.</param>
        /// <param name="port_context">Port context. Optional.</param>
        /// <param name="connection_request">Connect request message.</param>
        /// <param name="connection_message_attributes">Connect request attributes.</param>
        /// <param name="accept_connection">True to accept the connection.</param>
        /// <returns>The accepted port.</returns>
        public NtAlpcServer AcceptConnectPort(
            AlpcMessageFlags flags,
            ObjectAttributes object_attributes,
            AlpcPortAttributes port_attributes,
            IntPtr port_context,
            AlpcMessage connection_request,
            AlpcMessageAttributeSet connection_message_attributes,
            bool accept_connection)
        {
            return AcceptConnectPort(flags, object_attributes, port_attributes, port_context, 
                connection_request, connection_message_attributes, accept_connection, true).Result;
        }

        /// <summary>
        /// Accept a new connection on a port.
        /// </summary>
        /// <param name="flags">The message send flags.</param>
        /// <param name="connection_request">Connect request message.</param>
        /// <param name="connection_message_attributes">Connect request attributes.</param>
        /// <param name="accept_connection">True to accept the connection.</param>
        /// <returns>The accepted port.</returns>
        public NtAlpcServer AcceptConnectPort(
            AlpcMessageFlags flags,
            AlpcMessage connection_request,
            AlpcMessageAttributeSet connection_message_attributes,
            bool accept_connection)
        {
            return AcceptConnectPort(flags, null, null, IntPtr.Zero, connection_request, 
                connection_message_attributes, accept_connection);
        }
    }
}
