//  Copyright 2018 Google Inc. All Rights Reserved.
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
//  Based on PH source https://github.com/winsiderss/systeminformer/blob/85723cfb22b03ed7c068bbe784385dd64551a14b/phnt/include/ntafd.h

using NtCoreLib.Kernel.IO;
using NtCoreLib.Kernel.Net.Interop;
using NtCoreLib.Native.SafeBuffers;
using NtCoreLib.Utilities.Text;
using System;
using System.Net;
using System.Net.Sockets;

#nullable enable

namespace NtCoreLib.Kernel.Net;

/// <summary>
/// A class representing a low-level AFD socket.
/// </summary>
public class AfdSocket : IDisposable
{
    #region Private Members
    private readonly NtFile _socket;

    private AfdSocket(NtFile socket)
    {
        _socket = socket;
    }

    private static EaBuffer CreateOpenPacket(AfdEndpointFlags flags, GROUP group_id, AddressFamily address_family, SocketType socket_type, ProtocolType protocol_type, string transport_device_name)
    {
        AFD_OPEN_PACKET packet = new()
        {
            Flags = flags,
            GroupID = group_id,
            AddressFamily = address_family,
            SocketType = socket_type,
            Protocol = protocol_type,
            TransportDeviceNameLength = transport_device_name.Length * 2
        };

        using var buffer = packet.ToBuffer(packet.TransportDeviceNameLength, true);
        buffer.Data.WriteUnicodeString(transport_device_name + "\0");
        EaBuffer ea = new();
        ea.AddEntry("AfdOpenPacketXX", buffer.ToArray(), EaBufferEntryFlags.None);
        return ea;
    }

    private static void CopyAddressToBuffer(SafeBufferGeneric buffer, SocketAddress address)
    {
        for (int i = 0; i < address.Size; ++i)
        {
            buffer.Write((ulong)i, address[i]);
        }
    }

    private void Bind(EndPoint endpoint, BindShareAccess share_access)
    {
        AFD_BIND_INFO_TL bind = new();
        var addr = endpoint.Serialize();
        bind.ShareAccess = share_access;
        using var buffer = bind.ToBuffer(addr.Size, true);
        CopyAddressToBuffer(buffer.Data, addr);
        using var out_buffer = new SafeHGlobalBuffer(addr.Size);
        var result = _socket.DeviceIoControl(AfdIoControlCodes.IOCTL_AFD_BIND, buffer, out_buffer);
        out_buffer.Resize(result);
    }
    #endregion

    /// <summary>
    /// Create a new socket.
    /// </summary>
    /// <param name="address_family">The address address family.</param>
    /// <param name="socket_type">The socket type.</param>
    /// <param name="protocol_type">The protocol type.</param>
    /// <returns>The created low-level socket.</returns>
    public static AfdSocket Create(AddressFamily address_family, SocketType socket_type, ProtocolType protocol_type)
    {
        return new(NtFile.Create(@"\Device\Afd\Endpoint", FileAccessRights.GenericRead | FileAccessRights.GenericWrite | FileAccessRights.Synchronize,
            FileShareMode.Read | FileShareMode.Write, FileOpenOptions.SynchronousIoNonAlert, FileDisposition.Create,
            CreateOpenPacket(AfdEndpointFlags.None, GROUP.None, address_family, socket_type, protocol_type, string.Empty)));
    }

    /// <summary>
    /// Create a new IPv4 TCP socket.
    /// </summary>
    /// <returns>The created low-level socket.</returns>
    public static AfdSocket CreateTcpSocket()
    {
        AfdSocket socket = Create(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        socket.Connect(new IPEndPoint(IPAddress.Loopback, 12345));
        return socket;
    }

    /// <summary>
    /// Connect the socket to an endpoint.
    /// </summary>
    /// <param name="endpoint">The endpoint to connect to.</param>
    public void Connect(EndPoint endpoint)
    {
        Bind(new IPEndPoint(IPAddress.Any, 0), BindShareAccess.AFD_WILDCARDADDRESS);
        SocketAddress address = endpoint.Serialize();
        AFD_CONNECT_JOIN_INFO_TL connect = new();
        using var buffer = connect.ToBuffer(address.Size, true);
        CopyAddressToBuffer(buffer.Data, address);
        _socket.DeviceIoControl(AfdIoControlCodes.IOCTL_AFD_CONNECT, buffer, SafeHGlobalBuffer.Null);
    }

    /// <summary>
    /// Write a string to the socket in ASCII.
    /// </summary>
    /// <param name="s">The string to write.</param>
    public void Write(string s)
    {
        byte[] data = BinaryEncoding.Instance.GetBytes(s);
        _socket.Write(data);
    }

    /// <summary>
    /// Read a string from the socket in ASCII.
    /// </summary>
    /// <param name="max_length">The max length of the string to read.</param>
    /// <returns>The read string.</returns>
    public string Read(int max_length = 1024)
    {
        return BinaryEncoding.Instance.GetString(_socket.Read(max_length));
    }

    /// <summary>
    /// Dispose of the socket.
    /// </summary>
    public void Dispose()
    {
        _socket.Dispose();
    }
}
