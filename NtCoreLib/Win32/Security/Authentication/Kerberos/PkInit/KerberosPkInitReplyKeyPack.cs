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

using NtApiDotNet.Utilities.ASN1;
using NtApiDotNet.Utilities.ASN1.Builder;
using System;
using System.IO;

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos.PkInit
{
    /// <summary>
    /// ReplyKeyPack value for PKINIT.
    /// </summary>
    public sealed class KerberosPkInitReplyKeyPack : IDERObject
    {
        /// <summary>
        /// The reply key for the AS-REP.
        /// </summary>
        public KerberosAuthenticationKey ReplyKey { get; }

        /// <summary>
        /// A checksum over the AS-REQ which sent the request.
        /// </summary>
        public KerberosChecksum AsChecksum { get; }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="reply_key">The reply key for the AS-REP.</param>
        /// <param name="as_checksum">A checksum over the AS-REQ which sent the request.</param>
        public KerberosPkInitReplyKeyPack(KerberosAuthenticationKey reply_key, KerberosChecksum as_checksum)
        {
            ReplyKey = reply_key ?? throw new ArgumentNullException(nameof(reply_key));
            AsChecksum = as_checksum ?? throw new ArgumentNullException(nameof(as_checksum));
        }

        internal static KerberosPkInitReplyKeyPack Parse(byte[] data, KerberosPrincipalName name, string realm)
        {
            DERValue[] values = DERParser.ParseData(data);

            if (values.Length != 1 || !values[0].CheckSequence())
                throw new InvalidDataException();
            KerberosAuthenticationKey reply_key = null;
            KerberosChecksum as_checksum = null;
            foreach (var next in values[0].Children)
            {
                if (next.Type != DERTagType.ContextSpecific)
                    throw new InvalidDataException();
                switch (next.Tag)
                {
                    case 0:
                        reply_key = KerberosAuthenticationKey.Parse(next.Children[0], realm, name);
                        break;
                    case 1:
                        as_checksum = KerberosChecksum.Parse(next.Children[0]);
                        break;
                    default:
                        throw new InvalidDataException();
                }
            }

            if (reply_key == null || as_checksum == null)
                throw new InvalidDataException();

            return new KerberosPkInitReplyKeyPack(reply_key, as_checksum);
        }

        /*
        ReplyKeyPack ::= SEQUENCE {
          replyKey                [0] EncryptionKey,
                   -- Contains the session key used to encrypt the
                   -- enc-part field in the AS-REP, i.e., the
                   -- AS reply key.
          asChecksum              [1] Checksum,
                  -- Contains the checksum of the AS-REQ
                  -- corresponding to the containing AS-REP.
                  -- The checksum is performed over the type AS-REQ.
                  -- The protocol key [RFC3961] of the checksum is the
                  -- replyKey and the key usage number is 6.
                  -- If the replyKey's enctype is "newer" [RFC4120]
                  -- [RFC4121], the checksum is the required
                  -- checksum operation [RFC3961] for that enctype.
                  -- The client MUST verify this checksum upon receipt
                  -- of the AS-REP.
          ...
       }
        */
        void IDERObject.Write(DERBuilder builder)
        {
            using (var seq = builder.CreateSequence())
            {
                builder.WriteContextSpecific(0, ReplyKey);
                builder.WriteContextSpecific(1, AsChecksum);
            }
        }
    }
}
