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

using NtCoreLib.Net.Sockets.Interop;
using NtCoreLib.Utilities.Data;
using System;
using System.Collections.Generic;

namespace NtCoreLib.Net.Sockets.HyperV;

/// <summary>
/// Utilities for HyperV sockets.
/// </summary>
public static class HyperVSocketUtils
{
    private delegate bool GetAddressDelegate(out string address);

    private static Guid? GetAddress(GetAddressDelegate func) 
    {
        if (func(out string address))
            return Guid.Parse(address);
        return null;
    }

    /// <summary>
    /// Get the socket table for HyperV sockets.
    /// </summary>
    /// <param name="listener">True to query listeners.</param>
    /// <param name="partition">Specify the partition to query.</param>
    /// <returns>The list of hyperv socket table entries.</returns>
    public static IEnumerable<HyperVSocketTableEntry> GetSocketTable(bool listener, Guid partition)
    {
        using NtFile file = NtFile.Create(@"\Device\HvSocketSystem\HvSocketControl", 
            FileAccessRights.MaximumAllowed, FileShareMode.None, FileOpenOptions.None, FileDisposition.Create, null);
        byte[] buffer = file.DeviceIoControl(new NtIoControlCode(listener ? 0x21C01C : 0x21C020), partition.ToByteArray(), 0x10000);
        DataReader reader = new(buffer);
        int count = reader.ReadInt32();
        reader.ReadInt32(); // Padding.
        List<HyperVSocketTableEntry> table = new();
        while (count > 0)
        {
            table.Add(new HyperVSocketTableEntry(reader));
            count--;
        }
        return table.AsReadOnly();
    }

    /// <summary>
    /// Get the local HyperV socket address.
    /// </summary>
    public static Guid? LocalAddress => GetAddress(SocketNativeMethods.GetHvSocketLocalAddress);

    /// <summary>
    /// Get the parent HyperV socket address.
    /// </summary>
    public static Guid? ParentAddress => GetAddress(SocketNativeMethods.GetHvSocketParentAddress);

    /// <summary>
    /// Get the silo host HyperV socket address.
    /// </summary>
    public static Guid? SiloHostAddress => GetAddress(SocketNativeMethods.GetHvSocketSiloHostAddress);
}