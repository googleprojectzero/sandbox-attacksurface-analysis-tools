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

using System;
using System.Collections;
using System.Text;

namespace NtCoreLib.Win32.Security.Authentication.Kerberos;

/// <summary>
/// Class to represent a PAC_ATTRIBUTES_INFO entry.
/// </summary>
public sealed class KerberosAuthorizationDataPACAttributes : KerberosAuthorizationDataPACEntry
{
    private readonly BitArray _flags;

    /// <summary>
    /// The PAC was requested (PAC_WAS_REQUESTED)
    /// </summary>
    public bool PACWasRequested => _flags[0];
    /// <summary>
    /// The PAC was given implicitly (PAC_WAS_GIVEN_IMPLICITLY)
    /// </summary>
    public bool PACWasGivenImplicitly => _flags[1];

    private KerberosAuthorizationDataPACAttributes(byte[] data, BitArray flags)
        : base(KerberosAuthorizationDataPACEntryType.Attributes, data)
    {
        _flags = flags;
    }

    internal static bool Parse(byte[] data, out KerberosAuthorizationDataPACEntry entry)
    {
        entry = null;
        if (data.Length < 4)
            return false;

        int bits = BitConverter.ToInt32(data, 0);
        if (bits < 2)
            return false;

        int[] words = new int[(data.Length - 4) / 4];
        Buffer.BlockCopy(data, 4, words, 0, words.Length * 4);
        entry = new KerberosAuthorizationDataPACAttributes(data, new BitArray(words));
        return true;
    }

    private protected override void FormatData(StringBuilder builder)
    {
        builder.AppendLine($"PAC was requested: {PACWasRequested}");
        builder.AppendLine($"PAC was given    : {PACWasGivenImplicitly}");
    }
}
