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

using NtCoreLib.Utilities.ASN1;
using NtCoreLib.Utilities.ASN1.Builder;
using System;
using System.IO;

namespace NtCoreLib.Win32.Security.Authentication.Kerberos;

/// <summary>
/// The supported transited encoding types.
/// </summary>
public enum KerberosTransitedEncodingType
{
    /// <summary>
    /// None.
    /// </summary>
    None = 0,
    /// <summary>
    /// X.500 Compress.
    /// </summary>
    X500Compress = 1,
}

/// <summary>
/// Class to represent a Kerberos Transiting Encoding.
/// </summary>
public sealed class KerberosTransitedEncoding : IDERObject
{
    /// <summary>
    /// Transited encoding type.
    /// </summary>
    public KerberosTransitedEncodingType TransitedType { get; }

    /// <summary>
    /// Transited encoding data.
    /// </summary>
    public byte[] Data { get; }

    /// <summary>
    /// Constructor.
    /// </summary>
    public KerberosTransitedEncoding() 
        : this(KerberosTransitedEncodingType.X500Compress, Array.Empty<byte>())
    {
    }

    /// <summary>
    /// Constructor.
    /// </summary>
    /// <param name="type">The transited encoding type.</param>
    /// <param name="data">The transited encoding data.</param>
    public KerberosTransitedEncoding(KerberosTransitedEncodingType type, byte[] data)
    {
        TransitedType = type;
        Data = data;
    }

    internal static KerberosTransitedEncoding Parse(DERValue value)
    {
        if (!value.CheckSequence())
            throw new InvalidDataException();
        KerberosTransitedEncodingType type = 0;
        byte[] data = null;
        foreach (var next in value.Children)
        {
            if (next.Type != DERTagType.ContextSpecific)
                throw new InvalidDataException();
            switch (next.Tag)
            {
                case 0:
                    type = (KerberosTransitedEncodingType)next.ReadChildInteger();
                    break;
                case 1:
                    data = next.ReadChildOctetString();
                    break;
                default:
                    throw new InvalidDataException();
            }
        }

        if (data == null)
            throw new InvalidDataException();
        return new KerberosTransitedEncoding(type, data);
    }

    void IDERObject.Write(DERBuilder builder)
    {
        using var seq = builder.CreateSequence();
        seq.WriteContextSpecific(0, (int)TransitedType);
        seq.WriteContextSpecific(1, Data);
    }
}
