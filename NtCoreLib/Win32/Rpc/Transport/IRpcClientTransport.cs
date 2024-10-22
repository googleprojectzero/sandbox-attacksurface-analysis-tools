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

using NtCoreLib.Ndr.Marshal;
using NtCoreLib.Ndr.Rpc;
using System;
using System.Collections.Generic;

namespace NtCoreLib.Win32.Rpc.Transport;

/// <summary>
/// Interface to implement an RPC client transport.
/// </summary>
public interface IRpcClientTransport : IDisposable
{
    /// <summary>
    /// Bind the RPC transport to a specified interface.
    /// </summary>
    /// <param name="interface_id">The interface ID to bind to.</param>
    void Bind(RpcSyntaxIdentifier interface_id);

    /// <summary>
    /// Create a NDR marshal buffer for this transport.
    /// </summary>
    /// <returns>The NDR marshal buffer.</returns>
    INdrMarshalBuffer CreateMarshalBuffer();

    /// <summary>
    /// Send and receive an RPC message.
    /// </summary>
    /// <param name="proc_num">The procedure number.</param>
    /// <param name="objuuid">The object UUID for the call.</param>
    /// <param name="ndr_buffer">Marshal NDR buffer for the call.</param>
    /// <returns>Client response from the send.</returns>
    INdrUnmarshalBuffer SendReceive(int proc_num, Guid? objuuid, INdrMarshalBuffer ndr_buffer);

    /// <summary>
    /// Add and authenticate a new security context.
    /// </summary>
    /// <param name="transport_security">The transport security for the context.</param>
    /// <returns>The created security context.</returns>
    RpcTransportSecurityContext AddSecurityContext(RpcTransportSecurity transport_security);

    /// <summary>
    /// Disconnect the transport.
    /// </summary>
    void Disconnect();

    /// <summary>
    /// Get whether the client is connected or not.
    /// </summary>
    bool Connected { get; }

    /// <summary>
    /// Get the endpoint the client is connected to.
    /// </summary>
    string Endpoint { get; }

    /// <summary>
    /// Get the transport protocol sequence.
    /// </summary>
    string ProtocolSequence { get; }

    /// <summary>
    /// Get whether the client has been authenticated.
    /// </summary>
    bool Authenticated { get; }

    /// <summary>
    /// Get the transport's authentication type.
    /// </summary>
    RpcAuthenticationType AuthenticationType { get; }

    /// <summary>
    /// Get the transport's authentication level.
    /// </summary>
    RpcAuthenticationLevel AuthenticationLevel { get; }

    /// <summary>
    /// Get information about the local server process, if known.
    /// </summary>
    RpcServerProcessInformation ServerProcess { get; }

    /// <summary>
    /// Get the current Call ID.
    /// </summary>
    int CallId { get; }

    /// <summary>
    /// Indicates if this connection supported multiple security context.
    /// </summary>
    bool SupportsMultipleSecurityContexts { get; }

    /// <summary>
    /// Get the list of negotiated security context.
    /// </summary>
    IReadOnlyList<RpcTransportSecurityContext> SecurityContext { get; }

    /// <summary>
    /// Get or set the current security context.
    /// </summary>
    RpcTransportSecurityContext CurrentSecurityContext { get; set; }

    /// <summary>
    /// Get whether the transport supports synchronous pipes.
    /// </summary>
    bool SupportsSynchronousPipes { get; }

    /// <summary>
    /// Specify flags to various aspects of this transport.
    /// </summary>
    RpcTransportTraceFlags TraceFlags { get; set; }

    /// <summary>
    /// The transfer syntax this transport is using.
    /// </summary>
    public RpcSyntaxIdentifier TransferSyntax { get; }
}
