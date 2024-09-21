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
using NtCoreLib.Security.Authorization;
using NtCoreLib.Utilities.Collections;
using NtCoreLib.Utilities.Reflection;
using System;
using System.Linq;

namespace NtCoreLib;

/// <summary>
/// Class to represent an ALPC client port.
/// </summary>
public class NtAlpcClient : NtAlpc
{
    #region Private Members
    private readonly Lazy<NtResult<AlpcServerSessionInformation>> _server_info;

    private static NtResult<NtAlpcClient> ConnectInternal(
        string port_name,
        ObjectAttributes port_object_attributes,
        ObjectAttributes object_attributes,
        AlpcPortAttributes port_attributes,
        AlpcMessageFlags flags,
        Sid required_server_sid,
        SecurityDescriptor server_security_requirements,
        AlpcMessage connection_message,
        AlpcSendMessageAttributes out_message_attributes,
        AlpcReceiveMessageAttributes in_message_attributes,
        NtWaitTimeout timeout,
        bool throw_on_error)
    {
        using var list = new DisposableList();
        var sid = list.AddSid(required_server_sid);
        var sd = list.AddSecurityDescriptor(server_security_requirements);
        var message = list.GetMessageBuffer(connection_message);
        var out_attr = list.GetAttributesBuffer(out_message_attributes);
        var in_attr = list.GetAttributesBuffer(in_message_attributes);

        SafeKernelObjectHandle handle;
        NtStatus status;

        if (port_object_attributes != null)
        {
            status = NtSystemCalls.NtAlpcConnectPortEx(out handle,
                port_object_attributes, object_attributes, port_attributes,
                flags, sd, message, message.GetOptionalLength(), out_attr, in_attr, timeout?.Timeout);
        }
        else
        {
            status = NtSystemCalls.NtAlpcConnectPort(out handle,
                new UnicodeString(port_name), object_attributes, port_attributes,
                flags, sid, message, message.GetOptionalLength(), out_attr, in_attr, timeout?.Timeout);
        }
        return status.CreateResult(throw_on_error, () =>
        {
            var client = new NtAlpcClient(handle);
            connection_message?.FromSafeBuffer(message, client);
            in_message_attributes?.FromSafeBuffer(in_attr, client, connection_message);
            return client;
        });
    }
    #endregion

    #region Constructors

    internal NtAlpcClient(SafeKernelObjectHandle handle)
: base(handle)
    {
        _server_info = new Lazy<NtResult<AlpcServerSessionInformation>>(() => Query<AlpcServerSessionInformation>(AlpcPortInformationClass.AlpcServerSessionInformation, default, false));
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
        AlpcSendMessageAttributes out_message_attributes,
        AlpcReceiveMessageAttributes in_message_attributes,
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
        AlpcSendMessageAttributes out_message_attributes,
        AlpcReceiveMessageAttributes in_message_attributes,
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
        AlpcSendMessageAttributes out_message_attributes,
        AlpcReceiveMessageAttributes in_message_attributes,
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
        AlpcSendMessageAttributes out_message_attributes,
        AlpcReceiveMessageAttributes in_message_attributes,
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

    #region Public Methods

    /// <summary>
    /// Get the server process information.
    /// </summary>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The process information.</returns>
    [SupportedVersion(SupportedVersion.Windows10_19H1)]
    public NtResult<NtProcessInformation> GetServerProcess(bool throw_on_error)
    {
        return Query<AlpcServerSessionInformation>(AlpcPortInformationClass.AlpcServerSessionInformation, default, throw_on_error).Map(
            r => NtSystemInfo.GetProcessInformationExtended().FirstOrDefault(p => p.ProcessId == r.ProcessId)
            ?? new NtProcessInformation(r.ProcessId, r.SessionId));
    }

    /// <summary>
    /// Get the server process information.
    /// </summary>
    /// <returns>The process information.</returns>
    [SupportedVersion(SupportedVersion.Windows10_19H1)]
    public NtProcessInformation GetServerProcess()
    {
        return GetServerProcess(true).Result;
    }

    #endregion

    #region Public Properties
    /// <summary>
    /// Get the server process ID.
    /// </summary>
    [SupportedVersion(SupportedVersion.Windows10_19H1)]
    public int ServerProcessId => _server_info.Value.GetResultOrDefault().ProcessId;

    /// <summary>
    /// Get the server session ID.
    /// </summary>
    [SupportedVersion(SupportedVersion.Windows10_19H1)]
    public int ServerSessionId => _server_info.Value.GetResultOrDefault().SessionId;
    #endregion
}
