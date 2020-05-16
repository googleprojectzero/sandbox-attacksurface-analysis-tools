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

using NtApiDotNet.Utilities.ASN1;
using NtApiDotNet.Utilities.Text;
using System;
using System.IO;
using System.Text;

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos
{
#pragma warning disable 1591
    /// <summary>
    /// Flags for GSSAPI Checksum.
    /// </summary>
    [Flags]
    public enum KerberosChecksumGSSApiFlags
    {
        None = 0,
        Delegate = 1,
        Mutual = 2,
        Replay = 4,
        Sequence = 8,
        Confidentiality = 0x10,
        Integrity = 0x20,
        Identity = 0x2000
    }
#pragma warning restore 1591

    /// <summary>
    /// A kerberos checksum in GSS API Format.
    /// </summary>
    public class KerberosChecksumGSSApi : KerberosChecksum
    {
        /// <summary>
        /// Channel binding hash.
        /// </summary>
        public byte[] ChannelBinding { get; private set; }

        /// <summary>
        /// Flags for checksum.
        /// </summary>
        public KerberosChecksumGSSApiFlags ContextFlags { get; private set; }

        /// <summary>
        /// Delegation option identifier.
        /// </summary>
        public int DelegationOptionIdentifier { get; private set; }

        /// <summary>
        /// KRB_CRED structure when in delegation.
        /// </summary>
        public KerberosCredential Credentials { get; private set; }

        /// <summary>
        /// Additional extension data.
        /// </summary>
        public byte[] Extensions { get; private set; }

        internal override void Format(StringBuilder builder)
        {
            builder.AppendLine("Checksum        : GSSAPI");
            builder.AppendLine($"Channel Binding : {NtObjectUtils.ToHexString(ChannelBinding)}");
            builder.AppendLine($"Context Flags   : {ContextFlags}");
            if (Credentials != null)
            {
                builder.AppendLine($"Delegate Opt ID : {DelegationOptionIdentifier}");
                builder.AppendLine(Credentials.Format());
            }
            if (Extensions != null)
            {
                HexDumpBuilder hex = new HexDumpBuilder(false, true, true, false, 0);
                hex.Append(Extensions);
                hex.Complete();
                builder.AppendLine(hex.ToString());
            }
        }

        private KerberosChecksumGSSApi(KerberosChecksumType type, byte[] data) 
            : base(type, data)
        {
        }

        internal void Decrypt(KerberosKeySet keyset)
        {
            Credentials = (KerberosCredential)Credentials.Decrypt(keyset);
        }

        internal static bool Parse(byte[] data, out KerberosChecksum checksum)
        {
            checksum = null;

            try
            {
                KerberosChecksumGSSApi ret = new KerberosChecksumGSSApi(KerberosChecksumType.GSSAPI, data);

                BinaryReader reader = new BinaryReader(new MemoryStream(data));
                int binding_length = reader.ReadInt32();
                ret.ChannelBinding = reader.ReadAllBytes(binding_length);
                ret.ContextFlags = (KerberosChecksumGSSApiFlags)reader.ReadInt32();
                if (ret.ContextFlags.HasFlagSet(KerberosChecksumGSSApiFlags.Delegate))
                {
                    ret.DelegationOptionIdentifier = reader.ReadUInt16();
                    int cred_length = reader.ReadUInt16();
                    byte[] cred = reader.ReadAllBytes(cred_length);

                    DERValue[] values = DERParser.ParseData(cred, 0);
                    if (!KerberosCredential.TryParse(cred, values, out KerberosCredential cred_token))
                        return false;
                    ret.Credentials = cred_token;
                }
                if (reader.RemainingLength() > 0)
                {
                    ret.Extensions = reader.ReadToEnd();
                }

                checksum = ret;
                return true;
            }
            catch (EndOfStreamException)
            {
            }

            return false;
        }
    }
}
