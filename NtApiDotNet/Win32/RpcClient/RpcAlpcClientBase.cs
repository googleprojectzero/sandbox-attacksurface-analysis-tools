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

using NtApiDotNet.Ndr;
using System;

namespace NtApiDotNet.Win32.RpcClient
{
    /// <summary>
    /// Base class for an RPC ALPC client.
    /// </summary>
    public abstract class RpcAlpcClientBase : IDisposable
    {
        #region Private Members
        private readonly Guid _interface_id;
        private readonly Version _interface_version;
        private NtAlpcClient _client;
        private int _call_id;

        private static AlpcPortAttributes CreatePortAttributes(SecurityQualityOfService sqos)
        {
            AlpcPortAttributeFlags flags = AlpcPortAttributeFlags.AllowDupObject | AlpcPortAttributeFlags.AllowImpersonation | AlpcPortAttributeFlags.WaitablePort;
            if (!NtObjectUtils.IsWindows81OrLess)
            {
                flags |= AlpcPortAttributeFlags.AllowMultiHandleAttribute;
            }

            return new AlpcPortAttributes()
            {
                DupObjectTypes = AlpcHandleObjectType.AllObjects,
                MemoryBandwidth = new IntPtr(0),
                Flags = AlpcPortAttributeFlags.AllowDupObject | AlpcPortAttributeFlags.AllowImpersonation | AlpcPortAttributeFlags.WaitablePort,
                MaxMessageLength = new IntPtr(0x1000),
                MaxPoolUsage = new IntPtr(-1),
                MaxSectionSize = new IntPtr(-1),
                MaxViewSize = new IntPtr(-1),
                MaxTotalSectionSize = new IntPtr(-1),
                SecurityQos = sqos?.ToStruct() ?? new SecurityQualityOfServiceStruct(SecurityImpersonationLevel.Impersonation, SecurityContextTrackingMode.Static, false)
            };
        }

        private static NtAlpcClient ConnectPort(string path, SecurityQualityOfService sqos)
        {
            AlpcReceiveMessageAttributes in_attr = new AlpcReceiveMessageAttributes();
            return NtAlpcClient.Connect(path, null,
                CreatePortAttributes(sqos), AlpcMessageFlags.SyncRequest, null, null, null, in_attr, NtWaitTimeout.FromSeconds(5));
        }

        private static void CheckForFault(SafeHGlobalBuffer buffer, LRPC_MESSAGE_TYPE message_type)
        {
            var header = buffer.Read<LRPC_HEADER>(0);
            if (header.MessageType != LRPC_MESSAGE_TYPE.lmtFault && header.MessageType != message_type)
            {
                throw new ArgumentException($"Invalid response message type {header.MessageType}");
            }

            if (header.MessageType == LRPC_MESSAGE_TYPE.lmtFault)
            {
                var fault = buffer.GetStructAtOffset<LRPC_FAULT_MESSAGE>(0);
                throw new RpcFaultException(fault);
            }
        }

        private void BindInterface()
        {
            AlpcMessageType<LRPC_BIND_MESSAGE> bind_msg = new AlpcMessageType<LRPC_BIND_MESSAGE>(new LRPC_BIND_MESSAGE(_interface_id, _interface_version));
            AlpcMessageRaw resp_msg = new AlpcMessageRaw(0x1000);

            using (AlpcReceiveMessageAttributes recv_attr = new AlpcReceiveMessageAttributes())
            {
                _client.SendReceive(AlpcMessageFlags.SyncRequest, bind_msg, null, resp_msg, recv_attr, NtWaitTimeout.Infinite);
                using (var buffer = resp_msg.Data.ToBuffer())
                {
                    CheckForFault(buffer, LRPC_MESSAGE_TYPE.lmtBind);
                    var value = buffer.Read<LRPC_BIND_MESSAGE>(0);
                    if (value.RpcStatus != 0)
                    {
                        throw new NtException(NtObjectUtils.MapDosErrorToStatus(value.RpcStatus));
                    }
                }
            }
        }

        private string LookupEndpoint()
        {
            var endpoint = RpcEndpointMapper.MapServerToAlpcEndpoint(_interface_id, _interface_version);
            if (endpoint == null || string.IsNullOrEmpty(endpoint.EndpointPath))
            {
                throw new ArgumentException($"Can't find endpoint for {_interface_id} {_interface_version}");
            }
            return endpoint.EndpointPath;
        }

        private NdrUnmarshalBuffer HandleLargeResponse(AlpcMessageRaw message, SafeStructureInOutBuffer<LRPC_LARGE_RESPONSE_MESSAGE> response, AlpcReceiveMessageAttributes attributes)
        {
            if (!attributes.HasValidAttribute(AlpcMessageAttributeFlags.View))
            {
                throw new ArgumentException("Large response received but no data view available");
            }

            return new NdrUnmarshalBuffer(attributes.DataView.ReadBytes(response.Result.LargeDataSize), attributes.Handles);
        }

        private NdrUnmarshalBuffer HandleImmediateResponse(AlpcMessageRaw message, SafeStructureInOutBuffer<LRPC_IMMEDIATE_RESPONSE_MESSAGE> response, AlpcReceiveMessageAttributes attributes, int data_length)
        {
            return new NdrUnmarshalBuffer(response.Data.ToArray(), attributes.Handles);
        }

        private NdrUnmarshalBuffer HandleResponse(AlpcMessageRaw message, AlpcReceiveMessageAttributes attributes, int call_id)
        {
            using (var buffer = message.Data.ToBuffer())
            {
                CheckForFault(buffer, LRPC_MESSAGE_TYPE.lmtResponse);
                // Get data as safe buffer.
                var response = buffer.Read<LRPC_IMMEDIATE_RESPONSE_MESSAGE>(0);
                if (response.CallId != call_id)
                {
                    throw new ArgumentException("Mismatched Call ID");
                }

                if ((response.Flags & LRPC_RESPONSE_MESSAGE_FLAGS.ViewPresent) == LRPC_RESPONSE_MESSAGE_FLAGS.ViewPresent)
                {
                    return HandleLargeResponse(message, buffer.GetStructAtOffset<LRPC_LARGE_RESPONSE_MESSAGE>(0), attributes);
                }
                return HandleImmediateResponse(message, buffer.GetStructAtOffset<LRPC_IMMEDIATE_RESPONSE_MESSAGE>(0), attributes, message.DataLength);
            }
        }

        private void ClearAttributes(AlpcMessage msg, AlpcReceiveMessageAttributes attributes)
        {
            AlpcMessageAttributeFlags flags = attributes.ValidAttributes & (AlpcMessageAttributeFlags.View | AlpcMessageAttributeFlags.Handle);
            if (!msg.ContinuationRequired || flags == 0)
            {
                return;
            }

            _client.Send(AlpcMessageFlags.None, msg, attributes.ToContinuationAttributes(flags), NtWaitTimeout.Infinite);
        }

        private NdrUnmarshalBuffer SendAndReceiveLarge(int proc_num, NdrMarshalBuffer ndr_buffer, byte[] buffer)
        {
            LRPC_LARGE_REQUEST_MESSAGE req_msg = new LRPC_LARGE_REQUEST_MESSAGE()
            {
                Header = new LRPC_HEADER(LRPC_MESSAGE_TYPE.lmtRequest),
                BindingId = 0,
                CallId = _call_id++,
                ProcNum = proc_num,
                LargeDataSize = buffer.Length,
                Flags = LRPC_REQUEST_MESSAGE_FLAGS.ViewPresent
            };

            if (ObjectUuid != Guid.Empty)
            {
                req_msg.ObjectUuid = ObjectUuid;
                req_msg.Flags |= LRPC_REQUEST_MESSAGE_FLAGS.ObjectUuid;
            }

            var send_msg = new AlpcMessageType<LRPC_LARGE_REQUEST_MESSAGE>(req_msg);
            var resp_msg = new AlpcMessageRaw(0x1000);
            AlpcSendMessageAttributes send_attr = new AlpcSendMessageAttributes();

            if (ndr_buffer.Handles.Count > 0)
            {
                send_attr.AddHandles(ndr_buffer.Handles);
            }

            using (var port_section = _client.CreatePortSection(AlpcCreatePortSectionFlags.Secure, buffer.Length))
            {
                using (var data_view = port_section.CreateSectionView(AlpcDataViewAttrFlags.Secure | AlpcDataViewAttrFlags.AutoRelease, buffer.Length))
                {
                    data_view.WriteBytes(buffer);
                    send_attr.Add(data_view.ToMessageAttribute());
                    using (var recv_attr = new AlpcReceiveMessageAttributes())
                    {
                        _client.SendReceive(AlpcMessageFlags.SyncRequest, send_msg, send_attr, resp_msg, recv_attr, NtWaitTimeout.Infinite);
                        NdrUnmarshalBuffer unmarshal = HandleResponse(resp_msg, recv_attr, req_msg.CallId);
                        ClearAttributes(resp_msg, recv_attr);
                        return unmarshal;
                    }
                }
            }
        }

        private NdrUnmarshalBuffer SendAndReceiveImmediate(int proc_num, NdrMarshalBuffer ndr_buffer, byte[] buffer)
        {
            LRPC_IMMEDIATE_REQUEST_MESSAGE req_msg = new LRPC_IMMEDIATE_REQUEST_MESSAGE()
            {
                Header = new LRPC_HEADER(LRPC_MESSAGE_TYPE.lmtRequest),
                BindingId = 0,
                CallId = _call_id++,
                ProcNum = proc_num,
            };

            if (ObjectUuid != Guid.Empty)
            {
                req_msg.ObjectUuid = ObjectUuid;
                req_msg.Flags |= LRPC_REQUEST_MESSAGE_FLAGS.ObjectUuid;
            }

            AlpcMessageType<LRPC_IMMEDIATE_REQUEST_MESSAGE> send_msg = new AlpcMessageType<LRPC_IMMEDIATE_REQUEST_MESSAGE>(req_msg, buffer);
            AlpcMessageRaw resp_msg = new AlpcMessageRaw(0x1000);
            AlpcSendMessageAttributes send_attr = new AlpcSendMessageAttributes();
            if (ndr_buffer.Handles.Count > 0)
            {
                send_attr.AddHandles(ndr_buffer.Handles);
            }

            using (AlpcReceiveMessageAttributes recv_attr = new AlpcReceiveMessageAttributes())
            {
                _client.SendReceive(AlpcMessageFlags.SyncRequest, send_msg, send_attr, resp_msg, recv_attr, NtWaitTimeout.Infinite);
                NdrUnmarshalBuffer unmarshal = HandleResponse(resp_msg, recv_attr, req_msg.CallId);
                ClearAttributes(resp_msg, recv_attr);
                return unmarshal;
            }
        }

        #endregion

        #region Constructors

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="interface_id">The interface ID.</param>
        /// <param name="interface_version">Version of the interface.</param>
        protected RpcAlpcClientBase(Guid interface_id, Version interface_version)
        {
            _interface_id = interface_id;
            _interface_version = interface_version;
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="interface_id">The interface ID as a string.</param>
        /// <param name="major">Major version of the interface.</param>
        /// <param name="minor">Minor version of the interface.</param>
        protected RpcAlpcClientBase(string interface_id, int major, int minor) 
            : this(new Guid(interface_id), new Version(major, minor))
        {
        }

        #endregion

        #region Protected Methods

        /// <summary>
        /// Send and receive an RPC message.
        /// </summary>
        /// <param name="proc_num">The procedure number.</param>
        /// <param name="ndr_buffer">Marshal NDR buffer for the call.</param>
        /// <returns>Unmarshal NDR buffer for the result.</returns>
        protected NdrUnmarshalBuffer SendReceive(int proc_num, NdrMarshalBuffer ndr_buffer)
        {
            if (!Connected)
            {
                throw new InvalidOperationException("RPC client is not connected.");
            }

            byte[] buffer = ndr_buffer.ToArray();
            if (buffer.Length > 0xF00)
            {
                return SendAndReceiveLarge(proc_num, ndr_buffer, buffer);
            }
            return SendAndReceiveImmediate(proc_num, ndr_buffer, buffer);
        }

        #endregion

        #region Public Properties

        /// <summary>
        /// Get whether the client is connected or not.
        /// </summary>
        public bool Connected => _client != null && !_client.Handle.IsInvalid;

        /// <summary>
        /// Get the ALPC port path that we connected to.
        /// </summary>
        public string AlpcPath { get; private set; }

        /// <summary>
        /// Get the current Call ID.
        /// </summary>
        public int CallId => _call_id;

        /// <summary>
        /// Get or set the current Object UUID used for calls.
        /// </summary>
        public Guid ObjectUuid { get; set; }

        #endregion

        #region Public Methods

        /// <summary>
        /// Connect the client to an ALPC port.
        /// </summary>
        /// <param name="alpc_path">The path to the ALPC port.</param>
        /// <param name="security_quality_of_service">The security quality of service for the port.</param>
        public void Connect(string alpc_path, SecurityQualityOfService security_quality_of_service)
        {
            if (Connected)
            {
                throw new InvalidOperationException("RPC client is already connected.");
            }

            if (string.IsNullOrEmpty(alpc_path))
            {
                alpc_path = LookupEndpoint();
            }
            else if (!alpc_path.StartsWith(@"\"))
            {
                alpc_path = $@"\RPC Control\{alpc_path}";
            }
            AlpcPath = alpc_path;
            _client = ConnectPort(alpc_path, security_quality_of_service);
            _call_id = 1;
            BindInterface();
        }

        /// <summary>
        /// Connect the client to an ALPC port.
        /// </summary>
        /// <param name="alpc_path">The path to the ALPC port. If an empty string the endpoint will be looked up in the endpoint mapped.</param>
        public void Connect(string alpc_path)
        {
            Connect(alpc_path, null);
        }

        /// <summary>
        /// Connect the client to an ALPC port.
        /// </summary>
        /// <remarks>The ALPC endpoint will be looked up in the endpoint mapper.</remarks>
        public void Connect()
        {
            Connect(null);
        }

        /// <summary>
        /// Dispose of the client.
        /// </summary>
        public virtual void Dispose()
        {
            _client?.Dispose();
            _client = null;
        }

        /// <summary>
        /// Disconnect the client.
        /// </summary>
        public void Disconnect()
        {
            Dispose();
        }

        #endregion
    }
}
