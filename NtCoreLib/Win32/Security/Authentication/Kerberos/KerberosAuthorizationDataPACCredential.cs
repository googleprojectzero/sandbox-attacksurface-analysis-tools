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

using NtCoreLib.Ndr.Marshal;
using NtCoreLib.Utilities.Text;
using NtCoreLib.Win32.Security.Authentication.Kerberos.Ndr;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace NtCoreLib.Win32.Security.Authentication.Kerberos;

/// <summary>
/// Class to represent PAC supplemental credentials.
/// </summary>
public sealed class KerberosAuthorizationDataPACCredential : KerberosAuthorizationDataPACEntry
{
    #region Public Properties
    /// <summary>
    /// The credentials version.
    /// </summary>
    public int Version { get; }

    /// <summary>
    /// The encryption type for the credentials.
    /// </summary>
    public KerberosEncryptionType EncryptionType { get; }

    /// <summary>
    /// The encrypted serialized data.
    /// </summary>
    public byte[] SerializedData { get;}
    #endregion

    #region Public Members
    /// <summary>
    /// Decrypt and parse the list of supplemental credentials.
    /// </summary>
    /// <param name="key">The key to decrypt the credentials. This is usually the AP-REP's reply key.</param>
    /// <returns>The list of supplement credentials.</returns>
    public IEnumerable<SecPkgSupplementalCredential> Decrypt(KerberosAuthenticationKey key)
    {
        byte[] decrypted = key.Decrypt(SerializedData, KerberosKeyUsage.KerbNonKerbSalt);
        var creds = PacCredentialDataParser.Decode(new NdrPickledType(decrypted));
        List<SecPkgSupplementalCredential> ret = new();
        if (creds.HasValue)
        {
            ret.AddRange(creds.Value.Credentials.Select(c => new SecPkgSupplementalCredential(c.PackageName.ToString(), c.Credentials)));
        }
        return ret.AsReadOnly();
    }
    #endregion

    #region Private Members
    private KerberosAuthorizationDataPACCredential(byte[] data, int version, KerberosEncryptionType encryption_type, byte[] serialized_data)
        : base(KerberosAuthorizationDataPACEntryType.Credentials, data)
    {
        if (serialized_data is null)
        {
            throw new ArgumentNullException(nameof(serialized_data));
        }
        Version = version;
        EncryptionType = encryption_type;
        SerializedData = serialized_data;
    }

    private protected override void FormatData(StringBuilder builder)
    {
        builder.AppendLine($"Version          : {Version}");
        builder.AppendLine($"Encryption Type  : {EncryptionType}");
        builder.AppendLine($"Serialized Data  :");
        HexDumpBuilder hex = new(false, false, true, false, 0);
        hex.Append(SerializedData);
        hex.Complete();
        builder.Append(hex.ToString());
    }
    #endregion

    #region Internal Members
    internal static bool Parse(byte[] data, out KerberosAuthorizationDataPACEntry entry)
    {
        entry = null;
        if (data.Length < 8)
            return false;

        BinaryReader reader = new(new MemoryStream(data));
        int version = reader.ReadInt32();
        var encryption_type = (KerberosEncryptionType)reader.ReadInt32();

        entry = new KerberosAuthorizationDataPACCredential(data, version, encryption_type, reader.ReadToEnd());
        return true;
    }
    #endregion
}
