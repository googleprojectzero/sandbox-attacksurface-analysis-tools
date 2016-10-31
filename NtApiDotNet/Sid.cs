//  Copyright 2016 Google Inc. All Rights Reserved.
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//  http ://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

using System;
using System.Collections.Generic;
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
    /// Represents an identifier authority for a SID.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public sealed class SidIdentifierAuthority
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6)]
        private byte[] _value;

        /// <summary>
        /// Get a reference to the identifier authority. This can be used to modify the value
        /// </summary>
        public byte[] Value
        {
            get
            {
                return _value;
            }
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        public SidIdentifierAuthority()
        {
            _value = new byte[6];
        }

        /// <summary>
        /// Construct from an existing authority array.
        /// </summary>
        /// <param name="authority">The authority, must be 6 bytes in length.</param>
        /// <exception cref="ArgumentOutOfRangeException">Thrown if authority is not the correct length.</exception>
        public SidIdentifierAuthority(byte[] authority)
        {
            if (authority.Length != 6)
            {
                throw new ArgumentOutOfRangeException("authority", "Authority must be 6 bytes in size");
            }

            _value = (byte[])authority.Clone();
        }

        /// <summary>
        /// Constructor from a simple predefined authority.
        /// </summary>
        /// <param name="authority">The predefined authority.</param>
        public SidIdentifierAuthority(SecurityAuthority authority)
            : this(new byte[6] { 0, 0, 0, 0, 0, (byte)authority })
        {
        }

        /// <summary>
        /// Compares authority to another.
        /// </summary>
        /// <param name="obj">The other authority to compare against.</param>
        /// <returns>True if authority is equal.</returns>
        public override bool Equals(object obj)
        {
            SidIdentifierAuthority auth = obj as SidIdentifierAuthority;
            if (auth == null)
                return false;

            if (!base.Equals(obj))
            {
                return false;
            }

            for (int i = 0; i < 6; i++)
            {
                if (_value[i] != auth._value[i])
                {
                    return false;
                }
            }

            return true;
        }

        /// <summary>
        /// Get hash code.
        /// </summary>
        /// <returns>The authority hash code.</returns>
        public override int GetHashCode()
        {
            int result = 0;
            foreach (byte b in _value)
            {
                result += b;
            }
            return result;
        }
    }

    /// <summary>
    /// Class to represent a Security Identifier.
    /// </summary>
    public sealed class Sid
    {
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
        public Sid(SafeBuffer sid) : this(sid.DangerousGetHandle())
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
        /// Convert the SID to a safe buffer.
        /// </summary>
        /// <returns>The safe buffer containing the SID.</returns>
        public SafeSidBufferHandle ToSafeBuffer()
        {
            SafeSidBufferHandle sid;
            NtRtl.RtlAllocateAndInitializeSidEx(Authority,
                (byte)SubAuthorities.Count, SubAuthorities.ToArray(), out sid).ToNtException();
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
        /// Compares two sids to see if their prefixes are the same.
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
            Sid sid = obj as Sid;
            if (sid == null)
            {
                return false;
            }

            if (Authority.Equals(sid.Authority))
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
            if (System.Object.ReferenceEquals(a, b))
            {
                return true;
            }

            if (System.Object.ReferenceEquals(a, null))
            {
                return false;
            }

            if (System.Object.ReferenceEquals(b, null))
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
                return NtSecurity.LookupAccountSid(this) ?? ToString();
            }
        }
    }

    /// <summary>
    /// Static methods to get some known SIDs.
    /// </summary>
    public static class KnownSids
    {
        /// <summary>
        /// NULL SID
        /// </summary>
        public static Sid Null { get { return new Sid(SecurityAuthority.Null, 0); } }
        /// <summary>
        /// Everyone SID
        /// </summary>
        public static Sid World { get { return new Sid(SecurityAuthority.World, 0); } }
        /// <summary>
        /// Local user SID
        /// </summary>
        public static Sid Local { get { return new Sid(SecurityAuthority.Local, 0); } }
        /// <summary>
        /// CREATOR OWNER SID
        /// </summary>
        public static Sid CreatorOwner { get { return new Sid(SecurityAuthority.Creator, 0); } }
        /// <summary>
        /// CREATOR GROUP SID
        /// </summary>
        public static Sid CreatorGroup { get { return new Sid(SecurityAuthority.Creator, 1); } }
        /// <summary>
        /// Service SID
        /// </summary>
        public static Sid Service { get { return new Sid(SecurityAuthority.Nt, 6); } }
        /// <summary>
        /// ANONYMOUS LOGON SID
        /// </summary>
        public static Sid Anonymous { get { return new Sid(SecurityAuthority.Nt, 7); } }
        /// <summary>
        /// Authenticated Users SID
        /// </summary>
        public static Sid AuthenticatedUsers { get { return new Sid(SecurityAuthority.Nt, 11); } }
        /// <summary>
        /// RESTRICTED SID
        /// </summary>
        public static Sid Restricted { get { return new Sid(SecurityAuthority.Nt, 12); } }
        /// <summary>
        /// LOCAL SYSTEM SID
        /// </summary>
        public static Sid LocalSystem { get { return new Sid(SecurityAuthority.Nt, 18); } }
        /// <summary>
        /// LOCAL SERVICE SID
        /// </summary>
        public static Sid LocalService { get { return new Sid(SecurityAuthority.Nt, 19); } }
        /// <summary>
        /// NETWORK SERVICE SID
        /// </summary>
        public static Sid NetworkService { get { return new Sid(SecurityAuthority.Nt, 20); } }
    }
}
