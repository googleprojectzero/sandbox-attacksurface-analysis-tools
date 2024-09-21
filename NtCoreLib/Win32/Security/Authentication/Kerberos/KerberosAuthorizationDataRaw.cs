//  Copyright 2022 Google LLC. All Rights Reserved.
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

using NtCoreLib.Utilities.Text;
using System.Text;

namespace NtCoreLib.Win32.Security.Authentication.Kerberos;

/// <summary>
/// Class to represent an unparsed authorization data entry.
/// </summary>
public sealed class KerberosAuthorizationDataRaw : KerberosAuthorizationData
{
    /// <summary>
    /// Constructor.
    /// </summary>
    /// <param name="type">The type of data.</param>
    /// <param name="data">The raw data for the entry.</param>
    public KerberosAuthorizationDataRaw(KerberosAuthorizationDataType type, byte[] data) : base(type)
    {
        Data = data.CloneBytes();
    }

    /// <summary>
    /// Data bytes.
    /// </summary>
    public byte[] Data { get; }

    private protected override byte[] GetData()
    {
        return Data;
    }

    private protected override void FormatData(StringBuilder builder)
    {
        HexDumpBuilder hex = new(false, false, true, false, 0);
        hex.Append(Data);
        hex.Complete();
        builder.Append(hex.ToString());
    }
}
