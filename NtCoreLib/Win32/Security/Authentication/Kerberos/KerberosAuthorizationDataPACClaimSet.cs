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

using NtApiDotNet.Ndr.Marshal;
using NtApiDotNet.Utilities.Memory;
using NtApiDotNet.Win32.Security.Authentication.Kerberos.Ndr;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos
{
    /// <summary>
    /// Source of a set of claims.
    /// </summary>
    public enum KerberosClaimsSource
    {
        /// <summary>
        /// From Active Directory.
        /// </summary>
        ActiveDirectory = 1,
        /// <summary>
        /// From a certificate.
        /// </summary>
        Certificate = 2,
    }

    /// <summary>
    /// A single claim set.
    /// </summary>
    public class KerberosClaimsArray
    {
        /// <summary>
        /// The source of the claims array.
        /// </summary>
        public KerberosClaimsSource Source { get; }

        /// <summary>
        /// The list of claim attributes.
        /// </summary>
        public IReadOnlyList<ClaimSecurityAttribute> Claims { get; }

        internal KerberosClaimsArray(KerberosClaimsSource source, IEnumerable<ClaimSecurityAttribute> claims)
        {
            Source = source;
            Claims = claims.ToList().AsReadOnly();
        }
    }

    /// <summary>
    /// Class representing a Claims Set in the PAC.
    /// </summary>
    public class KerberosAuthorizationDataPACClaimSet : KerberosAuthorizationDataPACEntry
    {
        /// <summary>
        /// List of claims arrays.
        /// </summary>
        public IReadOnlyList<KerberosClaimsArray> ClaimsArray { get; }

        private static ClaimSecurityAttribute ConvertToClaim(CLAIM_ENTRY entry)
        {
            switch (entry.ClaimType.Value)
            {
                case 1:
                    return new ClaimSecurityAttribute(entry.Id, ClaimSecurityValueType.Int64, 0, entry.Values.ValueInt64.Int64Values.GetValue().Cast<object>());
                case 2:
                    return new ClaimSecurityAttribute(entry.Id, ClaimSecurityValueType.UInt64, 0, 
                        entry.Values.ValueUInt64.Uint64Values.GetValue().Select(l => (ulong)l).Cast<object>());
                case 3:
                    return new ClaimSecurityAttribute(entry.Id, ClaimSecurityValueType.String, 0, entry.Values.ValueString.StringValues.GetValue());
                case 4:
                    return new ClaimSecurityAttribute(entry.Id, ClaimSecurityValueType.Boolean, 0, 
                        entry.Values.ValueBoolean.BooleanValues.GetValue().Select(l => l != 0).Cast<object>());
                default:
                    return new ClaimSecurityAttribute(entry.Id, ClaimSecurityValueType.Int64, 0, new object[0]);
            }
        }

        private KerberosAuthorizationDataPACClaimSet(KerberosAuthorizationDataPACEntryType type, byte[] data, IReadOnlyList<KerberosClaimsArray> claims_array) 
            : base(type, data)
        {
            ClaimsArray = claims_array;
        }

        private static NtResult<byte[]> DecompressBuffer(CLAIMS_SET_METADATA set)
        {
            RtlCompressionFormat format = (RtlCompressionFormat)set.usCompressionFormat.Value;
            if (format == RtlCompressionFormat.None)
                return set.ClaimsSet.GetValue().CreateResult();
            if (!NtObjectUtils.IsWindows)
                return NtStatus.STATUS_INVALID_DEVICE_STATE.CreateResultFromError<byte[]>(false);
            return NtCompression.DecompressBuffer(format, set.ClaimsSet, set.ulUncompressedClaimsSetSize, false);
        }

        internal static bool Parse(KerberosAuthorizationDataPACEntryType type, byte[] data, out KerberosAuthorizationDataPACEntry entry)
        {
            entry = null;
            try
            {
                var set = ClaimSetMetadataParser.Decode(new NdrPickledType(data));
                if (!set.HasValue || set.Value.ClaimsSet == null)
                    return false;

                var claims_buffer = DecompressBuffer(set.Value);
                if (!claims_buffer.IsSuccess)
                    return false;

                var claims = ClaimSetParser.Decode(new NdrPickledType(claims_buffer.Result));
                if (!claims.HasValue || claims.Value.ClaimsArrays == null)
                    return false;

                List<KerberosClaimsArray> claims_array = new List<KerberosClaimsArray>();

                foreach (var claim in claims.Value.ClaimsArrays.GetValue())
                {
                    KerberosClaimsSource source = (KerberosClaimsSource)claim.usClaimsSourceType.Value;
                    claims_array.Add(new KerberosClaimsArray(source, claim.ClaimEntries.GetValue().Select(ConvertToClaim)));
                }

                entry = new KerberosAuthorizationDataPACClaimSet(type, data, claims_array.AsReadOnly());
                return true;
            }
            catch
            {
                return false;
            }
        }

        private protected override void FormatData(StringBuilder builder)
        {
            foreach(var entry in ClaimsArray)
            {
                builder.AppendLine($"<{entry.Source} Claim>");
                foreach (var claim in entry.Claims)
                {
                    builder.AppendLine($"{claim.Name} - {claim.ValueType} - {string.Join(", ", claim.Values)}");
                }
            }
        }
    }
}
