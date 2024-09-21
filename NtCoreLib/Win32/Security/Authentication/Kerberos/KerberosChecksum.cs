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
using System.Security.Cryptography;
using System.Text;

namespace NtCoreLib.Win32.Security.Authentication.Kerberos;

/// <summary>
/// Class to represent a Kerberos Checksum.
/// </summary>
public class KerberosChecksum : IDERObject
{
    /// <summary>
    /// Type of kerberos checksum.
    /// </summary>
    public KerberosChecksumType ChecksumType { get;}
    /// <summary>
    /// The checksum value.
    /// </summary>
    public byte[] Checksum { get; }

    internal virtual void Format(StringBuilder builder)
    {
        builder.AppendLine($"Checksum        : {ChecksumType} - {NtObjectUtils.ToHexString(Checksum)}");
    }

    /// <summary>
    /// Constructor
    /// </summary>
    /// <param name="type">The type of checksum.</param>
    /// <param name="data">The checksum data.</param>
    public KerberosChecksum(KerberosChecksumType type, byte[] data)
    {
        ChecksumType = type;
        Checksum = data ?? throw new System.ArgumentNullException(nameof(data));
    }

    /// <summary>
    /// Create a kerberos checksum.
    /// </summary>
    /// <param name="key">The key for the hash algorithm.</param>
    /// <param name="data">The data to hash.</param>
    /// <param name="offset">Offset into the data to hash.</param>
    /// <param name="length">The length of the data to hash.</param>
    /// <param name="key_usage">The key usage.</param>
    /// <returns>The new kerberos checksum.</returns>
    public static KerberosChecksum Create(KerberosAuthenticationKey key, byte[] data, int offset, int length, KerberosKeyUsage key_usage)
    {
        return new KerberosChecksum(key.ChecksumType, key.ComputeHash(data, offset, length, key_usage));
    }

    /// <summary>
    /// Create a kerberos checksum.
    /// </summary>
    /// <param name="key">The key for the hash algorithm.</param>
    /// <param name="data">The data to hash.</param>
    /// <param name="key_usage">The key usage.</param>
    /// <returns>The new kerberos checksum.</returns>
    public static KerberosChecksum Create(KerberosAuthenticationKey key, byte[] data, KerberosKeyUsage key_usage)
    {
        return Create(key, data, 0, data.Length, key_usage);
    }

    /// <summary>
    /// Create a kerberos a non-keyed checksum.
    /// </summary>
    /// <param name="type">The type of checksum.</param>
    /// <param name="data">The data to hash.</param>
    /// <returns>The new kerberos checksum.</returns>
    public static KerberosChecksum Create(KerberosChecksumType type, byte[] data)
    {
        System.Security.Cryptography.HashAlgorithm alg = type switch
        {
            KerberosChecksumType.RSA_MD5 => MD5.Create(),
            _ => throw new ArgumentException($"Unsupported non-keyed hash algorithm: {type}", nameof(type)),
        };
        return new KerberosChecksum(type, alg.ComputeHash(data));
    }

    private protected virtual byte[] GetData()
    {
        return Checksum;
    }

    internal static KerberosChecksum Parse(DERValue value)
    {
        if (!value.CheckSequence())
            throw new InvalidDataException();
        KerberosChecksumType type = 0;
        byte[] data = null;
        foreach (var next in value.Children)
        {
            if (next.Type != DERTagType.ContextSpecific)
                throw new InvalidDataException();
            switch (next.Tag)
            {
                case 0:
                    type = (KerberosChecksumType)next.ReadChildInteger();
                    break;
                case 1:
                    data = next.ReadChildOctetString();
                    break;
                default:
                    throw new InvalidDataException();
            }
        }

        if (type == 0 || data == null)
            throw new InvalidDataException();
        if (type == KerberosChecksumType.GSSAPI && KerberosChecksumGSSApi.Parse(data, out KerberosChecksum chksum))
        {
            return chksum;
        }
        return new KerberosChecksum(type, data);
    }

    void IDERObject.Write(DERBuilder builder)
    {
        using var seq = builder.CreateSequence();
        seq.WriteContextSpecific(0, (int)ChecksumType);
        seq.WriteContextSpecific(1, GetData());
    }
}
