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
                var send_attr = list.AddAlpcAttributes(send_attributes);
                var recv_attr = list.AddAlpcAttributes(receive_attributes);
                NtStatus status = NtSystemCalls.NtAlpcSendWaitReceivePort(Handle, flags, send_msg,
                    send_attr, recv_msg, recv_length, recv_attr, timeout?.Timeout).ToNtException(throw_on_error);
                if (status.IsSuccess())
                {
                    send_attributes?.FromSafeBuffer(send_attr);
                    receive_attributes?.FromSafeBuffer(recv_attr);
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
            using (var list = new DisposableList())
            {
                var sid = list.AddSid(required_server_sid);
                var message = connection_message == null ? SafeAlpcPortMessageBuffer.Null :
                                    connection_message.Buffer;
                var message_length = connection_message == null ? null : new OptionalInt32(connection_message.TotalLength);
                var out_attr = list.AddAlpcAttributes(out_message_attributes);
                var in_attr = list.AddAlpcAttributes(in_message_attributes);

                return NtSystemCalls.NtAlpcConnectPort(out SafeKernelObjectHandle handle,
                    new UnicodeString(port_name), object_attributes, port_attributes,
                    flags, sid, message, message_length, out_attr, in_attr, timeout?.Timeout)
                    .CreateResult(throw_on_error, () => {
                        out_message_attributes?.FromSafeBuffer(out_attr);
                        in_message_attributes?.FromSafeBuffer(in_attr);
                        return new NtAlpcClient(handle);
                    });
            }
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
        public static NtResult<NtAlpcServer> Create(ObjectAttributes object_attributes, AlpcPortAttributes port_attributes, bool throw_on_error)
        {
            return NtSystemCalls.NtAlpcCreatePort(out SafeKernelObjectHandle handle, object_attributes, port_attributes).CreateResult(throw_on_error, () => new NtAlpcServer(handle));
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
    }
}
