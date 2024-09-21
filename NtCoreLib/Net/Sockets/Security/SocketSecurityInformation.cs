//  Copyright 2021 Google LLC. All Rights Reserved.
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

using NtCoreLib.Native.SafeBuffers;
using NtCoreLib.Net.Sockets.Interop;
using NtCoreLib.Win32;
using System;
using System.Runtime.InteropServices;

namespace NtCoreLib.Net.Sockets.Security;

/// <summary>
/// Class to represent current socket security configuration.
/// </summary>
public sealed class SocketSecurityInformation : IDisposable
{
    /// <summary>
    /// Access token for the peer application.
    /// </summary>
    public NtToken PeerApplicationToken { get; }

    /// <summary>
    /// Access token for the peer machine.
    /// </summary>
    public NtToken PeerMachineToken { get; }

    /// <summary>
    /// Socket security flags.
    /// </summary>
    public SocketSecurityQueryInformationFlags Flags;

    /// <summary>
    /// Security association ID for main mode.
    /// </summary>
    public ulong MmSaId { get; }

    /// <summary>
    /// Security association ID for quick mode.
    /// </summary>
    public ulong QmSaId { get; }

    /// <summary>
    /// Negotiation windows error.
    /// </summary>
    public Win32Error NegotiationWinerr { get; }

    /// <summary>
    /// Security association lookup context. Can be used to bypass security
    /// checks for querying the security association information from the
    /// firewall.
    /// </summary>
    public Guid SaLookupContext { get; }

    /// <summary>
    /// Dispose method.
    /// </summary>
    public void Dispose()
    {
        PeerApplicationToken?.Dispose();
        PeerMachineToken?.Dispose();
    }

    private static NtToken CreateToken(long handle)
    {
        if (handle == 0)
            return null;
        return NtToken.FromHandle(new IntPtr(handle), true);
    }

    internal SocketSecurityInformation(SafeStructureInOutBuffer<SOCKET_SECURITY_QUERY_INFO> buffer)
    {
        var query_info = buffer.Result;
        Flags = query_info.Flags;
        PeerApplicationToken = CreateToken(query_info.PeerApplicationAccessTokenHandle);
        PeerMachineToken = CreateToken(query_info.PeerMachineAccessTokenHandle);
        if (buffer.Length < Marshal.SizeOf(typeof(SOCKET_SECURITY_QUERY_INFO_IPSEC2))
            || query_info.SecurityProtocol != SOCKET_SECURITY_PROTOCOL.IPsec2)
        {
            return;
        }
        var query_info_2 = buffer.Read<SOCKET_SECURITY_QUERY_INFO_IPSEC2>(0);
        MmSaId = query_info_2.MmSaId;
        QmSaId = query_info_2.QmSaId;
        NegotiationWinerr = query_info_2.NegotiationWinerr;
        SaLookupContext = query_info_2.SaLookupContext;
    }
}
