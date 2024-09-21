//  Copyright 2020 Google Inc. All Rights Reserved.
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
using System.Collections.Generic;

namespace NtCoreLib.Net.Sockets.HyperV;

/// <summary>
/// GUIDs for HyperV Sockets.
/// </summary>
public static class HyperVSocketGuids
{
    private static Dictionary<Guid, string> _guid_to_name;

    private static Dictionary<Guid, string> GetGuidToName()
    {
        if (_guid_to_name == null)
        {
            _guid_to_name = new Dictionary<Guid, string>();
            foreach (var field in typeof(HyperVSocketGuids).GetFields())
            {
                if (field.FieldType == typeof(Guid))
                {
                    Guid g = (Guid)field.GetValue(null);
                    _guid_to_name.Add(g, field.Name);
                }
            }
        }
        return _guid_to_name;
    }

    /// <summary>
    /// Allows accepting connections from all partitions.
    /// </summary>
    public readonly static Guid HV_GUID_WILDCARD = Guid.Empty;
    /// <summary>
    /// Broadcast. Send to all sockets.
    /// </summary>
    public readonly static Guid HV_GUID_BROADCAST = new(0xFFFFFFFF, 0xFFFF, 0xFFFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
    /// <summary>
    /// Allows accepting connections form all child partitions.
    /// </summary>
    public readonly static Guid HV_GUID_CHILDREN = new(0x90db8b89, 0x0d35, 0x4f79, 0x8c, 0xe9, 0x49, 0xea, 0x0a, 0xc8, 0xb7, 0xcd);
    /// <summary>
    /// Connect or bind to the loopback address.
    /// </summary>
    public readonly static Guid HV_GUID_LOOPBACK = new(0xe0e16197, 0xdd56, 0x4a10, 0x91, 0x95, 0x5e, 0xe7, 0xa1, 0x55, 0xa8, 0x38);
    /// <summary>
    /// Connect to the parent container.
    /// </summary>
    public readonly static Guid HV_GUID_PARENT = new(0xa42e7cda, 0xd03f, 0x480c, 0x9c, 0xc2, 0xa4, 0xde, 0x20, 0xab, 0xb8, 0x78);
    /// <summary>
    /// Connect to the silo host container.
    /// </summary>
    public readonly static Guid HV_GUID_SILOHOST = new(0x36bd0c5c, 0x7276, 0x4223, 0x88, 0xba, 0x7d, 0x03, 0xb6, 0x54, 0xc5, 0x68);
    /// <summary>
    /// VSOCK template GUID.
    /// </summary>
    public readonly static Guid HV_GUID_VSOCK_TEMPLATE = new(0x00000000, 0xfacb, 0x11e6, 0xbd, 0x58, 0x64, 0x00, 0x6a, 0x79, 0x86, 0xd3);

    /// <summary>
    /// Create an address for a VSOCK port.
    /// </summary>
    /// <param name="vsock">The VSOCK port.</param>
    /// <returns>The address.</returns>
    public static Guid CreateVSockAddress(int vsock)
    {
        byte[] ba = HV_GUID_VSOCK_TEMPLATE.ToByteArray();
        Buffer.BlockCopy(new int[] { vsock }, 0, ba, 0, 4);
        return new Guid(ba);
    }

    /// <summary>
    /// Checks if an address is a VSOCK address.
    /// </summary>
    /// <param name="address">The address to check.</param>
    /// <returns>True if a VSOCK address.</returns>
    public static bool IsVSockAddress(Guid address)
    {
        byte[] ba = address.ToByteArray();
        ba[0] = 0;
        ba[1] = 0;
        ba[2] = 0;
        ba[3] = 0;
        return new Guid(ba) == HV_GUID_VSOCK_TEMPLATE;
    }

    /// <summary>
    /// Get the port for a VSOCK address.
    /// </summary>
    /// <param name="address">The address to query.</param>
    /// <returns>The VSOCK port.</returns>
    /// <exception cref="ArgumentException">Throw if not a valid VSOCK address.</exception>
    public static int GetVSockPort(Guid address)
    {
        if (!IsVSockAddress(address))
            throw new ArgumentException("Invalid VSock address.", nameof(address));
        return BitConverter.ToInt32(address.ToByteArray(), 0);
    }

    /// <summary>
    /// Convert an address to a string.
    /// </summary>
    /// <param name="address">The address to convert.</param>
    /// <returns>The converted address. If not symbolic name found will return the GUID as a string.</returns>
    public static string AddressToString(Guid address)
    {
        if (IsVSockAddress(address))
            return $"HV_GUID_VSOCK[{GetVSockPort(address)}]";
        var dict = GetGuidToName();
        if (dict.ContainsKey(address))
            return dict[address];
        return address.ToString();
    }
}
