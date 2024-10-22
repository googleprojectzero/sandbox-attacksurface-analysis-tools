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

using NtCoreLib.Kernel.Alpc;
using NtCoreLib.Native.SafeBuffers;
using NtCoreLib.Ndr.Marshal;
using NtCoreLib.Ndr.Rpc;
using NtCoreLib.Security.Token;
using NtCoreLib.Win32.Rpc.EndpointMapper;
using NtCoreLib.Win32.Rpc.Transport.Alpc;
using System;
using System.Collections.Generic;
using System.Linq;

namespace NtCoreLib.Win32.Rpc.Transport;

/// <summary>
/// RPC client transport over ALPC.
/// </summary>
public class RpcAlpcClientTransport : IRpcClientTransport
{
    #region Private Members
    private readonly RpcClientTransportTransferSyntax _transfer_syntax_bind;
    private NtAlpcClient _client;
    private readonly SecurityQualityOfService _sqos;
    private RpcSyntaxIdentifier _transfer_syntax;
    private int _binding_id;

    private static AlpcPortAttributes CreatePortAttributes(SecurityQualityOfService sqos)
    {
        AlpcPortAttributeFlags flags = AlpcPortAttributeFlags.AllowDupObject | 
            AlpcPortAttributeFlags.AllowImpersonation | AlpcPortAttributeFlags.WaitablePort;
        if (!NtObjectUtils.IsWindows81OrLess)
        {
            flags |= AlpcPortAttributeFlags.AllowMultiHandleAttribute;
        }

        return new AlpcPortAttributes()
        {
            DupObjectTypes = AlpcHandleObjectType.AllObjects,
            MemoryBandwidth = new IntPtr(0),
            Flags = flags,
            MaxMessageLength = new IntPtr(0x1000),
            MaxPoolUsage = new IntPtr(-1),
            MaxSectionSize = new IntPtr(-1),
            MaxViewSize = new IntPtr(-1),
            MaxTotalSectionSize = new IntPtr(-1),
            SecurityQos = sqos?.ToStruct() ?? 
                new SecurityQualityOfServiceStruct(SecurityImpersonationLevel.Impersonation, 
                SecurityContextTrackingMode.Static, false)
        };
    }

    private static NtAlpcClient ConnectPort(string path, SecurityQualityOfService sqos, RpcAlpcClientTransportConfiguration config)
    {
        NtWaitTimeout timeout = config?.ConnectTimeout ?? NtWaitTimeout.FromSeconds(5);

        AlpcReceiveMessageAttributes in_attr = new();
        if (config?.ServerSecurityRequirements != null)
        {
            using var port_attr = new ObjectAttributes(path);
            return NtAlpcClient.Connect(port_attr, null,
                CreatePortAttributes(sqos), AlpcMessageFlags.SyncRequest,
                config?.ServerSecurityRequirements, null, null, in_attr, timeout);
        }
        return NtAlpcClient.Connect(path, null,
            CreatePortAttributes(sqos), AlpcMessageFlags.SyncRequest,
            config?.RequiredServerSid, null, null, in_attr, timeout);
    }

    private static void CheckForFault(SafeHGlobalBuffer buffer, LRPC_MESSAGE_TYPE message_type)
    {
        var header = buffer.Read<LRPC_HEADER>(0);
        if (header.MessageType != LRPC_MESSAGE_TYPE.lmtFault && header.MessageType != message_type)
        {
            throw new RpcTransportException($"Invalid response message type {header.MessageType}");
        }

        if (header.MessageType == LRPC_MESSAGE_TYPE.lmtFault)
        {
            var fault = buffer.GetStructAtOffset<LRPC_FAULT_MESSAGE>(0);
            throw new RpcFaultException(fault);
        }
    }

    private void BindInterface(RpcSyntaxIdentifier interface_id)
    {
        LRPC_BIND_MESSAGE lpc_bind = new(interface_id)
        {
            TransferSyntaxSet = _transfer_syntax_bind switch
            {
                RpcClientTransportTransferSyntax.Dce => TransferSyntaxSetFlags.UseDce,
                RpcClientTransportTransferSyntax.Ndr64 => TransferSyntaxSetFlags.UseNdr64,
                RpcClientTransportTransferSyntax.Negotiate => TransferSyntaxSetFlags.UseDce | TransferSyntaxSetFlags.UseNdr64,
                _ => throw new ArgumentException("Invalid transfer syntax type."),
            }
        };
        var bind_msg = new AlpcMessageType<LRPC_BIND_MESSAGE>(lpc_bind);
        RpcTransportUtils.DumpBuffer(TraceFlags, RpcTransportTraceFlags.Transport, "ALPC BindInterface Send", bind_msg); 
        var recv_msg = new AlpcMessageRaw(0x1000);

        using var recv_attr = new AlpcReceiveMessageAttributes();
        _client.SendReceive(AlpcMessageFlags.SyncRequest, bind_msg, null, recv_msg, recv_attr, NtWaitTimeout.Infinite);
        RpcTransportUtils.DumpBuffer(TraceFlags, RpcTransportTraceFlags.Transport, "ALPC BindInterface Receive", recv_msg);
        using var buffer = recv_msg.Data.ToBuffer();
        CheckForFault(buffer, LRPC_MESSAGE_TYPE.lmtBind);
        var value = buffer.Read<LRPC_BIND_MESSAGE>(0);
        if (value.RpcStatus != 0)
        {
            throw new NtException(NtObjectUtils.MapDosErrorToStatus(value.RpcStatus));
        }
        if (value.TransferSyntaxSet.HasFlagSet(TransferSyntaxSetFlags.UseDce))
        {
            _transfer_syntax = RpcSyntaxIdentifier.DCETransferSyntax;
            _binding_id = value.DceNdrSyntaxIdentifier;
        }
        else if (value.TransferSyntaxSet.HasFlagSet(TransferSyntaxSetFlags.UseNdr64))
        {
            _transfer_syntax = RpcSyntaxIdentifier.NDR64TransferSyntax;
            _binding_id = value.Ndr64SyntaxIdentifier;
        }
        else
        {
            throw new RpcTransportException("Unknown RPC transfer syntax supported.");
        }
    }

    private INdrUnmarshalBuffer HandleLargeResponse(AlpcMessageRaw message, SafeStructureInOutBuffer<LRPC_LARGE_RESPONSE_MESSAGE> response, AlpcReceiveMessageAttributes attributes)
    {
        if (!attributes.HasValidAttribute(AlpcMessageAttributeFlags.View))
        {
            throw new RpcTransportException("Large response received but no data view available");
        }

        return new NdrUnmarshalBuffer(attributes.DataView.ReadBytes(response.Result.LargeDataSize), 
            attributes.Handles, ndr64: _transfer_syntax == RpcSyntaxIdentifier.NDR64TransferSyntax);
    }

    private INdrUnmarshalBuffer HandleImmediateResponse(AlpcMessageRaw message, SafeStructureInOutBuffer<LRPC_IMMEDIATE_RESPONSE_MESSAGE> response, AlpcReceiveMessageAttributes attributes, int data_length)
    {
        return new NdrUnmarshalBuffer(response.Data.ToArray(), attributes.Handles,
            ndr64: _transfer_syntax == RpcSyntaxIdentifier.NDR64TransferSyntax);
    }

    private INdrUnmarshalBuffer HandleResponse(AlpcMessageRaw message, AlpcReceiveMessageAttributes attributes, int call_id)
    {
        using var buffer = message.Data.ToBuffer();
        CheckForFault(buffer, LRPC_MESSAGE_TYPE.lmtResponse);
        // Get data as safe buffer.
        var response = buffer.Read<LRPC_IMMEDIATE_RESPONSE_MESSAGE>(0);
        if (response.CallId != call_id)
        {
            throw new RpcTransportException("Mismatched Call ID");
        }

        if ((response.Flags & LRPC_RESPONSE_MESSAGE_FLAGS.ViewPresent) == LRPC_RESPONSE_MESSAGE_FLAGS.ViewPresent)
        {
            return HandleLargeResponse(message, buffer.GetStructAtOffset<LRPC_LARGE_RESPONSE_MESSAGE>(0), attributes);
        }
        return HandleImmediateResponse(message, buffer.GetStructAtOffset<LRPC_IMMEDIATE_RESPONSE_MESSAGE>(0), attributes, message.DataLength);
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

    private INdrUnmarshalBuffer SendAndReceiveLarge(int proc_num, Guid? objuuid, byte[] ndr_buffer, IReadOnlyCollection<NdrSystemHandle> handles)
    {
        LRPC_LARGE_REQUEST_MESSAGE req_msg = new()
        {
            Header = new LRPC_HEADER(LRPC_MESSAGE_TYPE.lmtRequest),
            BindingId = _binding_id,
            CallId = CallId++,
            ProcNum = proc_num,
            LargeDataSize = ndr_buffer.Length,
            Flags = LRPC_REQUEST_MESSAGE_FLAGS.ViewPresent
        };

        if (objuuid.HasValue)
        {
            req_msg.ObjectUuid = objuuid.Value;
            req_msg.Flags |= LRPC_REQUEST_MESSAGE_FLAGS.ObjectUuid;
        }

        var send_msg = new AlpcMessageType<LRPC_LARGE_REQUEST_MESSAGE>(req_msg);
        var recv_msg = new AlpcMessageRaw(0x1000);
        var send_attr = new AlpcSendMessageAttributes();

        if (handles.Count > 0)
        {
            send_attr.AddHandles(handles.Select(h => new AlpcHandleMessageAttributeEntry(h.Handle, h.DesiredAccess)));
        }

        using var port_section = _client.CreatePortSection(AlpcCreatePortSectionFlags.Secure, ndr_buffer.Length);
        using var data_view = port_section.CreateSectionView(AlpcDataViewAttrFlags.Secure | AlpcDataViewAttrFlags.AutoRelease, ndr_buffer.Length);
        data_view.WriteBytes(ndr_buffer);
        send_attr.Add(data_view.ToMessageAttribute());
        using var recv_attr = new AlpcReceiveMessageAttributes();
        RpcTransportUtils.DumpBuffer(TraceFlags, RpcTransportTraceFlags.Transport, "ALPC Request Large", send_msg);
        _client.SendReceive(AlpcMessageFlags.SyncRequest, send_msg, send_attr, recv_msg, recv_attr, NtWaitTimeout.Infinite);
        RpcTransportUtils.DumpBuffer(TraceFlags, RpcTransportTraceFlags.Transport, "ALPC Response Large", recv_msg);
        INdrUnmarshalBuffer response = HandleResponse(recv_msg, recv_attr, req_msg.CallId);
        ClearAttributes(recv_msg, recv_attr);
        return response;
    }

    private INdrUnmarshalBuffer SendAndReceiveImmediate(int proc_num, Guid? objuuid, byte[] ndr_buffer, IReadOnlyCollection<NdrSystemHandle> handles)
    {
        LRPC_IMMEDIATE_REQUEST_MESSAGE req_msg = new()
        {
            Header = new LRPC_HEADER(LRPC_MESSAGE_TYPE.lmtRequest),
            BindingId = _binding_id,
            CallId = CallId++,
            ProcNum = proc_num,
        };

        if (objuuid.HasValue)
        {
            req_msg.ObjectUuid = objuuid.Value;
            req_msg.Flags |= LRPC_REQUEST_MESSAGE_FLAGS.ObjectUuid;
        }

        AlpcMessageType<LRPC_IMMEDIATE_REQUEST_MESSAGE> send_msg = new(req_msg, ndr_buffer);
        AlpcMessageRaw resp_msg = new(0x1000);
        AlpcSendMessageAttributes send_attr = new();

        if (handles.Count > 0)
        {
            send_attr.AddHandles(handles.Select(h => new AlpcHandleMessageAttributeEntry(h.Handle, h.DesiredAccess)));
        }

        using AlpcReceiveMessageAttributes recv_attr = new();
        RpcTransportUtils.DumpBuffer(TraceFlags, RpcTransportTraceFlags.Transport, "ALPC Request Immediate", send_msg);
        _client.SendReceive(AlpcMessageFlags.SyncRequest, send_msg, send_attr, resp_msg, recv_attr, NtWaitTimeout.Infinite);
        RpcTransportUtils.DumpBuffer(TraceFlags, RpcTransportTraceFlags.Transport, "ALPC Response Immediate", resp_msg);
        INdrUnmarshalBuffer response = HandleResponse(resp_msg, recv_attr, req_msg.CallId);
        ClearAttributes(resp_msg, recv_attr);
        return response;
    }

    private static string GetPathFromBinding(RpcStringBinding binding)
    {
        if (!binding.ProtocolSequence.Equals(RpcProtocolSequence.LRPC, StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException("RPC endpoint should have the LRPC protocol sequence.", nameof(binding));
        }

        if (string.IsNullOrEmpty(binding.Endpoint))
        {
            throw new ArgumentException("Must specify an endpoint to connect to");
        }

        if (!binding.Endpoint.StartsWith(@"\"))
        {
            return $@"\RPC Control\{binding.Endpoint}";
        }
        return binding.Endpoint;
    }
    #endregion

    #region Constructors
    /// <summary>
    /// Constructor.
    /// </summary>
    /// <param name="binding">The path to connect.</param>
    /// <param name="security_quality_of_service">Security QoS for the the transport.</param>
    /// <param name="config">The transport configuration for the connection.</param>
    public RpcAlpcClientTransport(RpcStringBinding binding, 
        SecurityQualityOfService security_quality_of_service, 
        RpcAlpcClientTransportConfiguration config) : this(GetPathFromBinding(binding), security_quality_of_service, config)
    {
    }

    /// <summary>
    /// Constructor.
    /// </summary>
    /// <param name="path">The path to connect. Should be an absolute path to the ALPC port.</param>
    /// <param name="security_quality_of_service">Security QoS for the the transport.</param>
    /// <param name="config">The transport configuration for the connection.</param>
    public RpcAlpcClientTransport(string path, SecurityQualityOfService security_quality_of_service, RpcAlpcClientTransportConfiguration config)
    {
        _client = ConnectPort(path, security_quality_of_service, config);
        _sqos = security_quality_of_service;
        _transfer_syntax_bind = config?.TransferSyntax ?? RpcClientTransportTransferSyntax.Dce;
        if (_transfer_syntax_bind == RpcClientTransportTransferSyntax.Ndr64)
        {
            throw new ArgumentException("Transport doesn't support NDR64.");
        }
        Endpoint = path;
    }
    #endregion

    #region Public Methods
    /// <summary>
    /// Bind the RPC transport to an interface.
    /// </summary>
    /// <param name="interface_id">The interface ID to bind to.</param>
    public void Bind(RpcSyntaxIdentifier interface_id)
    {
        CallId = 1;
        BindInterface(interface_id);
    }

    /// <summary>
    /// Send and receive an RPC message.
    /// </summary>
    /// <param name="proc_num">The procedure number.</param>
    /// <param name="objuuid">The object UUID for the call.</param>
    /// <param name="ndr_buffer">Marshal NDR buffer for the call.</param>
    /// <returns>Client response from the send.</returns>
    public INdrUnmarshalBuffer SendReceive(int proc_num, Guid? objuuid, INdrMarshalBuffer ndr_buffer)
    {
        byte[] ba = ndr_buffer.ToArray();
        return ba.Length > 0xF00
            ? SendAndReceiveLarge(proc_num, objuuid, ba, ndr_buffer.Handles)
            : SendAndReceiveImmediate(proc_num, objuuid, ba, ndr_buffer.Handles);
    }

    /// <summary>
    /// Create a NDR marshal buffer for this transport.
    /// </summary>
    /// <returns>The NDR marshal buffer.</returns>
    public INdrMarshalBuffer CreateMarshalBuffer()
    {
        return new NdrMarshalBuffer(default, _transfer_syntax == RpcSyntaxIdentifier.NDR64TransferSyntax);
    }

    /// <summary>
    /// Dispose of the client.
    /// </summary>
    public void Dispose()
    {
        _client?.Dispose();
        _client = null;
        _transfer_syntax = default;
    }

    /// <summary>
    /// Disconnect the client.
    /// </summary>
    public void Disconnect()
    {
        Dispose();
    }

    /// <summary>
    /// Add and authenticate a new security context.
    /// </summary>
    /// <param name="transport_security">The transport security for the context.</param>
    /// <returns>The created security context.</returns>
    public RpcTransportSecurityContext AddSecurityContext(RpcTransportSecurity transport_security)
    {
        throw new InvalidOperationException("Transport doesn't support multiple security context.");
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
    public string Endpoint { get; private set; }

    /// <summary>
    /// Get the current Call ID.
    /// </summary>
    public int CallId { get; private set; }

    /// <summary>
    /// Get the transport protocol sequence.
    /// </summary>
    public string ProtocolSequence => RpcProtocolSequence.LRPC;

    /// <summary>
    /// Get information about the local server process, if known.
    /// </summary>
    public RpcServerProcessInformation ServerProcess
    {
        get
        {
            if (!Connected)
                throw new InvalidOperationException("ALPC transport is not connected.");
            return new RpcServerProcessInformation(_client.ServerProcessId, _client.ServerSessionId);
        }
    }

    /// <summary>
    /// Get whether the client has been authenticated.
    /// </summary>
    public bool Authenticated => Connected;

    /// <summary>
    /// Get the transports authentication type.
    /// </summary>
    public RpcAuthenticationType AuthenticationType => Authenticated ? RpcAuthenticationType.WinNT : RpcAuthenticationType.None;

    /// <summary>
    /// Get the transports authentication level.
    /// </summary>
    public RpcAuthenticationLevel AuthenticationLevel => Authenticated ? RpcAuthenticationLevel.PacketPrivacy : RpcAuthenticationLevel.None;

    /// <summary>
    /// Indicates if this connection supported multiple security context.
    /// </summary>
    public bool SupportsMultipleSecurityContexts => false;

    /// <summary>
    /// Get the list of negotiated security context.
    /// </summary>
    public IReadOnlyList<RpcTransportSecurityContext> SecurityContext => 
        new List<RpcTransportSecurityContext>() { CurrentSecurityContext }.AsReadOnly();

    /// <summary>
    /// Get or set the current security context.
    /// </summary>
    public RpcTransportSecurityContext CurrentSecurityContext {
        get => new(this, new RpcTransportSecurity(_sqos)
        {
            AuthenticationType = AuthenticationType,
            AuthenticationLevel = AuthenticationLevel
        }, 0);
        set => throw new InvalidOperationException("Transport doesn't support multiple security context."); }

    /// <summary>
    /// Get whether the transport supports synchronous pipes.
    /// </summary>
    public bool SupportsSynchronousPipes => false;

    /// <summary>
    /// Specify flags to trace various aspects of this transport.
    /// </summary>
    public RpcTransportTraceFlags TraceFlags { get; set; }

    /// <summary>
    /// The transfer syntax this transport is using.
    /// </summary>
    public RpcSyntaxIdentifier TransferSyntax => _transfer_syntax;
    #endregion
}
