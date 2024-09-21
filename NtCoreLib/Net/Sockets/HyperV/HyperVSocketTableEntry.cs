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

using NtCoreLib.Utilities.Data;
using System;
using System.IO;

namespace NtCoreLib.Net.Sockets.HyperV;

/// <summary>
/// Entry for the HyperV socket table.
/// </summary>
public sealed class HyperVSocketTableEntry
{
    /// <summary>
    /// The socket system ID.
    /// </summary>
    public Guid SystemId { get; }

    /// <summary>
    /// The system ID name if known.
    /// </summary>
    public string SystemIdName => HyperVSocketGuids.AddressToString(SystemId);

    /// <summary>
    /// The socket VM ID.
    /// </summary>
    public Guid VmId { get; }

    /// <summary>
    /// The VM ID name if known.
    /// </summary>
    public string VmIdName => HyperVSocketGuids.AddressToString(VmId);

    /// <summary>
    /// The hosting process ID.
    /// </summary>
    public int ProcessId { get; }

    /// <summary>
    /// The path to the process.
    /// </summary>
    public string ImagePath => NtSystemInfo.GetProcessIdImagePath(ProcessId);

    /// <summary>
    /// The name of the process.
    /// </summary>
    public string ProcessName => Path.GetFileName(ImagePath);

    /// <summary>
    /// The timestamp for the socket.
    /// </summary>
    public long Timestamp { get; }

    /// <summary>
    /// Unknown value.
    /// </summary>
    public long Unknown { get; }

    internal HyperVSocketTableEntry(DataReader reader)
    {
        SystemId = reader.ReadGuid();
        VmId = reader.ReadGuid();
        ProcessId = reader.ReadInt32();
        reader.ReadInt32(); // Padding.
        Timestamp = reader.ReadInt64();
        Unknown = reader.ReadInt64();
    }
}
