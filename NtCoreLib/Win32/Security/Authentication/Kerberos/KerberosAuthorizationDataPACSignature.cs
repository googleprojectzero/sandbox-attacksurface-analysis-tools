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

using NtCoreLib.Win32.Security.Authentication.Kerberos.Builder;
using System;
using System.Text;

namespace NtCoreLib.Win32.Security.Authentication.Kerberos;

/// <summary>
/// Class to represent a PAC signature.
/// </summary>
public class KerberosAuthorizationDataPACSignature : KerberosAuthorizationDataPACEntry
{
    /// <summary>
    /// Signature type.
    /// </summary>
    public KerberosChecksumType SignatureType { get; }
    /// <summary>
    /// Signature.
    /// </summary>
    public byte[] Signature { get; }
    /// <summary>
    /// Read-only Domain Controller Identifier.
    /// </summary>
    public int? RODCIdentifier { get; }

    /// <summary>
    /// Convert to a builder.
    /// </summary>
    /// <returns>The builder object.</returns>
    public override KerberosAuthorizationDataPACEntryBuilder ToBuilder()
    {
        return new KerberosAuthorizationDataPACSignatureBuilder(PACType, SignatureType, Signature, RODCIdentifier);
    }

    /// <summary>
    /// Compare the signature against another.
    /// </summary>
    /// <param name="obj">The signature to check.</param>
    /// <returns>True if the signatures are equal.</returns>
    public override bool Equals(object obj)
    {
        if (!(obj is KerberosAuthorizationDataPACSignature other))
            return false;
        return other.SignatureType == SignatureType && other.RODCIdentifier == RODCIdentifier &&
            NtObjectUtils.EqualByteArray(other.Signature, Signature);
    }

    /// <summary>
    /// Calculate hash code.
    /// </summary>
    /// <returns>The hash code.</returns>
    public override int GetHashCode()
    {
        return SignatureType.GetHashCode() ^ RODCIdentifier.GetHashCode() 
            ^ NtObjectUtils.GetHashCodeByteArray(Signature);
    }

    private KerberosAuthorizationDataPACSignature(KerberosAuthorizationDataPACEntryType type, 
        byte[] data, KerberosChecksumType sig_type, byte[] signature, int? rodc_id)
        : base(type, data)
    {
        SignatureType = sig_type;
        Signature = signature;
        RODCIdentifier = rodc_id;
    }

    private protected override void FormatData(StringBuilder builder)
    {
        builder.AppendLine($"Signature Type   : {SignatureType}");
        builder.AppendLine($"Signature        : {NtObjectUtils.ToHexString(Signature)}");
        if (RODCIdentifier.HasValue)
        {
            builder.AppendLine($"RODC Identifier  : {RODCIdentifier}");
        }
    }

    internal static bool Parse(KerberosAuthorizationDataPACEntryType type, byte[] data, out KerberosAuthorizationDataPACEntry entry)
    {
        entry = null;

        if (data.Length < 4)
            return false;
        KerberosChecksumType signature_type = (KerberosChecksumType)BitConverter.ToInt32(data, 0);
        var signature_length = signature_type switch
        {
            KerberosChecksumType.HMAC_MD5 => 16,
            KerberosChecksumType.HMAC_SHA1_96_AES_128 or KerberosChecksumType.HMAC_SHA1_96_AES_256 => 12,
            _ => data.Length - 4,
        };
        byte[] signature = new byte[signature_length];
        Buffer.BlockCopy(data, 4, signature, 0, signature_length);
        int? rodc_id = null;
        int total_size = 4 + signature_length;
        if (data.Length - total_size >= 2)
        {
            rodc_id = BitConverter.ToUInt16(data, total_size);
        }
        entry = new KerberosAuthorizationDataPACSignature(type, data, signature_type, signature, rodc_id);
        return true;
    }
}
