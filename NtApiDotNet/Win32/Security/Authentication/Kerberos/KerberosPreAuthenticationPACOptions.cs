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
using System.Collections;
using System.IO;

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos
{
    /// <summary>
    /// Flags for the PA-PAC-OPTIONS pre-authentication data.
    /// </summary>
    [Flags]
    public enum KerberosPreAuthenticationPACOptionsFlags
    {
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
        None = 0,
        Claims = 1,
        BranchAware = 2,
        ForwardToFullDC = 4,
        ResourceBasedConstrainedDelegation = 8,
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
    }

    /// <summary>
    /// Class to specify the PA-PAC-OPTIONS pre-authentication data.
    /// </summary>
    public sealed class KerberosPreAuthenticationPACOptions : KerberosPreAuthenticationData
    {
        /// <summary>
        /// The PA-PAC-OPTIONS pre-authentication flags.
        /// </summary>
        public KerberosPreAuthenticationPACOptionsFlags Flags { get; }

        /// <summary>
        /// Constructor.
        /// </summary>
        public KerberosPreAuthenticationPACOptions(KerberosPreAuthenticationPACOptionsFlags flags) 
            : base(KerberosPreAuthenticationType.PA_PAC_OPTIONS)
        {
            Flags = flags;
        }

        private protected override byte[] GetData()
        {
            BitArray bits = new BitArray(32);
            if (Flags.HasFlagSet(KerberosPreAuthenticationPACOptionsFlags.Claims))
                bits[0] = true;
            if (Flags.HasFlagSet(KerberosPreAuthenticationPACOptionsFlags.BranchAware))
                bits[1] = true;
            if (Flags.HasFlagSet(KerberosPreAuthenticationPACOptionsFlags.ForwardToFullDC))
                bits[2] = true;
            if (Flags.HasFlagSet(KerberosPreAuthenticationPACOptionsFlags.ResourceBasedConstrainedDelegation))
                bits[3] = true;

            DERBuilder builder = new DERBuilder();
            using (var seq = builder.CreateSequence())
            {
                seq.WriteContextSpecific(0, bits);
            }
            return builder.ToArray();
        }

        internal static KerberosPreAuthenticationPACOptions Parse(byte[] data)
        {
            DERValue[] values = DERParser.ParseData(data, 0);
            if (values.Length != 1 || !values[0].CheckSequence())
                throw new InvalidDataException();
            BitArray bits = null;
            foreach (DERValue next in values[0].Children)
            {
                if (next.Type != DERTagType.ContextSpecific)
                    throw new InvalidDataException();
                switch (next.Tag)
                {
                    case 0:
                        bits = next.ReadChildBitString();
                        break;
                    default:
                        throw new InvalidDataException();
                }
            }
            if (bits == null || bits.Count < 4)
            {
                throw new InvalidDataException();
            }

            KerberosPreAuthenticationPACOptionsFlags flags = KerberosPreAuthenticationPACOptionsFlags.None;
            if (bits[0])
                flags |= KerberosPreAuthenticationPACOptionsFlags.Claims;
            if (bits[1])
                flags |= KerberosPreAuthenticationPACOptionsFlags.BranchAware;
            if (bits[2])
                flags |= KerberosPreAuthenticationPACOptionsFlags.ForwardToFullDC;
            if (bits[3])
                flags |= KerberosPreAuthenticationPACOptionsFlags.ResourceBasedConstrainedDelegation;
            return new KerberosPreAuthenticationPACOptions(flags);
        }
    }
}
