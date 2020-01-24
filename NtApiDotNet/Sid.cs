//  Copyright 2016 Google Inc. All Rights Reserved.
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
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;

namespace NtApiDotNet
{
    /// <summary>
    /// Predefined security authorities
    /// </summary>
    public enum SecurityAuthority : byte
    {
#pragma warning disable 1591
        Null = 0,
        World = 1,
        Local = 2,
        Creator = 3,
        NonUnique = 4,
        Nt = 5,
        ResourceManager = 9,
        Package = 15,
        Label = 16,
        ScopedPolicyId = 17,
        Authentication = 18,
        ProcessTrust = 19,
#pragma warning restore 1591
    }

    /// <summary>
    /// Class to represent a Security Identifier.
    /// </summary>
    public sealed class Sid
    {
        /// <summary>
        /// Maximum size of a SID buffer.
        /// </summary>
        public const int MaximumSidSize = 256;

        /// <summary>
        /// The SIDs authority.
        /// </summary>
        public SidIdentifierAuthority Authority { get; private set; }

        /// <summary>
        /// List of the SIDs sub authorities.
        /// </summary>
        public List<uint> SubAuthorities { get; private set; }

        private void InitializeFromPointer(IntPtr sid)
        {
            if (!NtRtl.RtlValidSid(sid))
                throw new NtException(NtStatus.STATUS_INVALID_SID);

            IntPtr authority = NtRtl.RtlIdentifierAuthoritySid(sid);
            Authority = (SidIdentifierAuthority)Marshal.PtrToStructure(authority, typeof(SidIdentifierAuthority));
            int sub_authority_count = Marshal.ReadByte(NtRtl.RtlSubAuthorityCountSid(sid));
            SubAuthorities = new List<uint>();
            for (int i = 0; i < sub_authority_count; ++i)
            {
                SubAuthorities.Add((uint)Marshal.ReadInt32(NtRtl.RtlSubAuthoritySid(sid, i), 0));
            }
        }

        /// <summary>
        /// Constructor for authority and sub authorities.
        /// </summary>
        /// <param name="authority">The identifier authority.</param>
        /// <param name="sub_authorities">The sub authorities.</param>
        public Sid(SidIdentifierAuthority authority, params uint[] sub_authorities)
        {
            Authority = new SidIdentifierAuthority(authority.Value);
            SubAuthorities = new List<uint>(sub_authorities);
        }

        /// <summary>
        /// Constructor for authority and sub authorities.
        /// </summary>
        /// <param name="authority">The identifier authority.</param>
        /// <param name="sub_authorities">The sub authorities.</param>
        public Sid(SecurityAuthority authority, params uint[] sub_authorities)
            : this(new SidIdentifierAuthority(authority), sub_authorities)
        {
        }

        /// <summary>
        /// Constructor from an unmanged buffer.
        /// </summary>
        /// <param name="sid">A pointer to a buffer containing a valid SID.</param>
        /// <exception cref="NtException">Thrown if the buffer is not valid.</exception>
        public Sid(IntPtr sid)
        {
            InitializeFromPointer(sid);
        }

        /// <summary>
        /// Constructor from an unmanged buffer.
        /// </summary>
        /// <param name="sid">A safe buffer containing a valid SID.</param>
        /// <exception cref="NtException">Thrown if the buffer is not valid.</exception>
        public Sid(SafeBuffer sid) 
            : this(sid.DangerousGetHandle())
        {
        }

        /// <summary>
        /// Constructor from a safe SID handle.
        /// </summary>
        /// <param name="sid">A safe SID handle containing a valid SID.</param>
        /// <exception cref="NtException">Thrown if the buffer is not valid.</exception>
        public Sid(SafeSidBufferHandle sid) 
            : this(sid.DangerousGetHandle())
        {
        }

        /// <summary>
        /// Constructor from an manged buffer.
        /// </summary>
        /// <param name="sid">A buffer containing a valid SID.</param>
        /// <exception cref="NtException">Thrown if the buffer is not valid.</exception>
        public Sid(byte[] sid)
        {
            using (SafeHGlobalBuffer buffer = new SafeHGlobalBuffer(sid))
            {
                InitializeFromPointer(buffer.DangerousGetHandle());
            }
        }

        /// <summary>
        /// Constructor from existing Sid.
        /// </summary>
        /// <param name="sid">The existing Sid.</param>
        public Sid(Sid sid) : this(sid.Authority, sid.SubAuthorities.ToArray())
        {
        }

        /// <summary>
        /// Constructor from an SDDL string.
        /// </summary>
        /// <param name="sid">The SID in SDDL format.</param>
        /// <example>
        /// new Sid("S-1-0-0");
        /// new Sid("WD");
        /// </example>
        /// <seealso cref="NtSecurity.LookupAccountName(string)"/>
        public Sid(string sid) : this(NtSecurity.SidFromSddl(sid))
        {
        }

        /// <summary>
        /// Construct a SID from a binary reader.
        /// </summary>
        /// <param name="reader">The binary reader.</param>
        internal Sid(BinaryReader reader)
        {
            int revision = reader.ReadByte();
            if (revision != 1)
            {
                throw new NtException(NtStatus.STATUS_INVALID_SID);
            }
            int subauth_count = reader.ReadByte();
            byte[] authority = reader.ReadAllBytes(6);
            List<uint> subauth = new List<uint>();
            for (int i = 0; i < subauth_count; ++i)
            {
                subauth.Add(reader.ReadUInt32());
            }

            SubAuthorities = subauth;
            Authority = new SidIdentifierAuthority(authority);
        }

        /// <summary>
        /// Convert the SID to a safe buffer.
        /// </summary>
        /// <returns>The safe buffer containing the SID.</returns>
        public SafeSidBufferHandle ToSafeBuffer()
        {
            SafeSidBufferHandle sid;
            try
            {
                NtRtl.RtlAllocateAndInitializeSidEx(Authority,
                    (byte)SubAuthorities.Count, SubAuthorities.ToArray(), out sid).ToNtException();
            }
            catch (EntryPointNotFoundException)
            {
                // If not found then we're on a downlevel platform, try and use the old version 
                // which is limited to 8 subauthorities.
                uint[] sub_authories = SubAuthorities.ToArray();
                if (sub_authories.Length != 8)
                {
                    Array.Resize(ref sub_authories, 8);
                }
                NtRtl.RtlAllocateAndInitializeSid(Authority, (byte)SubAuthorities.Count,
                    sub_authories[0], sub_authories[1], sub_authories[2], sub_authories[3],
                    sub_authories[4], sub_authories[5], sub_authories[6], sub_authories[7],
                    out sid).ToNtException();
            }
            return sid;
        }

        /// <summary>
        /// Convert to a managed byte array.
        /// </summary>
        /// <returns>The managed byte array.</returns>
        public byte[] ToArray()
        {
            using (SafeSidBufferHandle handle = ToSafeBuffer())
            {
                return NtObjectUtils.SafeHandleToArray(handle, handle.Length);
            }
        }

        /// <summary>
        /// Compares two sids to see if their prefixes are the same. The sids must have the same number of subauthorities.
        /// </summary>
        /// <param name="sid">The sid to compare against</param>
        /// <returns>True if the sids share a prefix.</returns>
        public bool EqualPrefix(Sid sid)
        {
            using (SafeSidBufferHandle sid1 = ToSafeBuffer(), sid2 = sid.ToSafeBuffer())
            {
                return NtRtl.RtlEqualPrefixSid(sid1, sid2);
            }
        }

        /// <summary>
        /// Compare two Sids.
        /// </summary>
        /// <param name="obj">The other Sid to compare.</param>
        /// <returns>True if the Sids are equal.</returns>
        public override bool Equals(object obj)
        {
            if (!(obj is Sid))
            {
                return false;
            }

            Sid sid = obj as Sid;

            if (!Authority.Equals(sid.Authority))
            {
                return false;
            }

            if (SubAuthorities.Count != sid.SubAuthorities.Count)
            {
                return false;
            }

            for (int i = 0; i < this.SubAuthorities.Count; ++i)
            {
                if (SubAuthorities[i] != sid.SubAuthorities[i])
                {
                    return false;
                }
            }

            return true;
        }

        /// <summary>
        /// Equality operator.
        /// </summary>
        /// <param name="a">Sid 1</param>
        /// <param name="b">Sid 2</param>
        /// <returns>True if the Sids are equal.</returns>
        public static bool operator ==(Sid a, Sid b)
        {
            if (ReferenceEquals(a, b))
            {
                return true;
            }

            if (a is null)
            {
                return false;
            }

            if (b is null)
            {
                return false;
            }

            return a.Equals(b);
        }

        /// <summary>
        /// Inequality operator.
        /// </summary>
        /// <param name="a">Sid 1</param>
        /// <param name="b">Sid 2</param>
        /// <returns>True if the Sids are not equal.</returns>
        public static bool operator !=(Sid a, Sid b)
        {
            return !(a == b);
        }

        /// <summary>
        /// Get hash code.
        /// </summary>
        /// <returns>The hash code.</returns>
        public override int GetHashCode()
        {
            int sub_hash_code = 0;
            foreach (uint sub_auth in SubAuthorities)
            {
                sub_hash_code ^= sub_auth.GetHashCode();
            }
            return Authority.GetHashCode() ^ sub_hash_code;
        }

        /// <summary>
        /// Convert to an SDDL format string.
        /// </summary>
        /// <returns>The SDDL format string (e.g. S-1-1-0)</returns>
        public override string ToString()
        {
            using (SafeSidBufferHandle sid = ToSafeBuffer())
            {
                UnicodeStringOut str = new UnicodeStringOut();
                NtRtl.RtlConvertSidToUnicodeString(ref str, sid.DangerousGetHandle(), true).ToNtException();
                try
                {
                    return str.ToString();
                }
                finally
                {
                    NtRtl.RtlFreeUnicodeString(ref str);
                }
            }
        }

        /// <summary>
        /// Get the account name of the SID or the SDDL form is no corresponding name.
        /// </summary>
        public string Name
        {
            get
            {
                return NtSecurity.GetNameForSid(this).Name;
            }
        }
    }
}
