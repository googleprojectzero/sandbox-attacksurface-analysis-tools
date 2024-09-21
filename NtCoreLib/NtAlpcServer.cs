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
using NtCoreLib.Native.SafeHandles;
using NtCoreLib.Utilities.Collections;
using System;

namespace NtCoreLib;

/// <summary>
/// Class to represent an ALPC server port.
/// </summary>
public class NtAlpcServer : NtAlpc
{
    #region Constructors
    internal NtAlpcServer(SafeKernelObjectHandle handle)
        : base(handle)
    {
    }
    #endregion

    #region Static Methods
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
        using var obj_attr = new ObjectAttributes(port_name, AttributeFlags.CaseInsensitive);
        return Create(obj_attr, port_attributes);
    }
    #endregion

    #region Public Methods
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
        AlpcSendMessageAttributes connection_message_attributes,
        bool accept_connection,
        bool throw_on_error)
    {
        if (connection_request == null)
        {
            throw new ArgumentNullException("Must specify a connection request message");
        }
        using var list = new DisposableList();
        return NtSystemCalls.NtAlpcAcceptConnectPort(out SafeKernelObjectHandle handle,
            Handle, flags, object_attributes, port_attributes, port_context,
            list.GetMessageBuffer(connection_request), list.GetAttributesBuffer(connection_message_attributes),
            accept_connection).CreateResult(throw_on_error, () => new NtAlpcServer(handle));
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
        AlpcSendMessageAttributes connection_message_attributes,
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
        AlpcSendMessageAttributes connection_message_attributes,
        bool accept_connection)
    {
        return AcceptConnectPort(flags, null, null, IntPtr.Zero, connection_request,
            connection_message_attributes, accept_connection);
    }
    #endregion
}
