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
                return (byte[])_value.Clone();
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

            if (base.Equals(obj))
            {
                return true;
            }

            for (int i = 0; i < _value.Length; i++)
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

        /// <summary>
        /// Determines if this is a specific security authority.
        /// </summary>
        /// <param name="authority">The security authority.</param>
        /// <returns>True if the security authority.</returns>
        public bool IsAuthority(SecurityAuthority authority)
        {
            return this.Equals(new SidIdentifierAuthority(authority));
        }

        private static bool IsSystemAuthority(byte[] value)
        {
            for (int i = 0; i < 5; ++i)
            {
                if (value[i] != 0)
                {
                    return false;
                }
            }
            return true;
        }

        /// <summary>
        /// Overridden ToString method.
        /// </summary>
        /// <returns>The security authority as a string.</returns>
        public override string ToString()
        {
            if (IsSystemAuthority(_value))
            {
                return ((SecurityAuthority)_value[5]).ToString();
            }

            byte[] temp = _value;
            Array.Resize(ref temp, 8);
            return String.Format("Authority {0}", BitConverter.ToInt64(temp, 0));
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
            if (Object.ReferenceEquals(a, b))
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

        private static string MakeFakeCapabilityName(string name)
        {
            List<string> parts = new List<string>();
            int start = 0;
            int index = 0;
            while (index < name.Length)
            {
                if (Char.IsUpper(name[index]))
                {
                    parts.Add(name.Substring(start, index - start));
                    start = index;
                }
                index++;
            }

            parts.Add(name.Substring(start));
            parts[0] = Char.ToUpper(parts[0][0]) + parts[0].Substring(1);

            return String.Format(@"NAMED CAPABILITIES\{0}", String.Join(" ", parts));
        }

        /// <summary>
        /// Get the account name of the SID or the SDDL form is no corresponding name.
        /// </summary>
        public string Name
        {
            get
            {
                string name = NtSecurity.LookupAccountSid(this);
                if (name == null && NtSecurity.IsCapabilitySid(this))
                {
                    // See if there's a known SID with this name.
                    name = NtSecurity.LookupKnownCapabilityName(this);
                    if (name != null)
                    {
                        name = MakeFakeCapabilityName(name);
                    }
                }
                else if (name == null && NtSecurity.IsPackageSid(this))
                {
                    name = NtSecurity.LookupPackageSid(this);
                }

                return name ?? ToString();
            }
        }
    }

    /// <summary>
    /// An enumeration to reference a known SID.
    /// </summary>
    public enum KnownSidValue
    {
        /// <summary>
        /// NULL SID
        /// </summary>
        Null,

        /// <summary>
        /// Everyone SID
        /// </summary>
        World,

        /// <summary>
        /// Local user SID
        /// </summary>
        Local,

        /// <summary>
        /// CREATOR OWNER SID
        /// </summary>
        CreatorOwner,

        /// <summary>
        /// CREATOR GROUP SID
        /// </summary>
        CreatorGroup,

        /// <summary>
        /// Service SID
        /// </summary>
        Service,

        /// <summary>
        /// ANONYMOUS LOGON SID
        /// </summary>
        Anonymous,

        /// <summary>
        /// Authenticated Users SID
        /// </summary>
        AuthenticatedUsers,

        /// <summary>
        /// RESTRICTED SID
        /// </summary>
        Restricted,

        /// <summary>
        /// LOCAL SYSTEM SID
        /// </summary>
        LocalSystem,

        /// <summary>
        /// LOCAL SERVICE SID
        /// </summary>
        LocalService,

        /// <summary>
        /// NETWORK SERVICE SID
        /// </summary>
        NetworkService,

        /// <summary>
        /// APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES SID
        /// </summary>
        AllApplicationPackages,

        /// <summary>
        /// APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES
        /// </summary>
        AllRestrictedApplicationPackages,

        /// <summary>
        /// NT SERVICE\TrustedInstaller
        /// </summary>
        TrustedInstaller,

        /// <summary>
        /// BUILTIN\Users
        /// </summary>
        BuiltinUsers,

        /// <summary>
        /// BUILTIN\Administrators
        /// </summary>
        BuiltinAdministrators,

        /// <summary>
        /// APPLICATION PACKAGE AUTHORITY\Your Internet connection
        /// </summary>
        CapabilityInternetClient,

        /// <summary>
        /// APPLICATION PACKAGE AUTHORITY\Your Internet connection, including incoming connections from the Internet
        /// </summary>
        CapabilityInternetClientServer,

        /// <summary>
        /// APPLICATION PACKAGE AUTHORITY\Your home or work networks
        /// </summary>
        CapabilityPrivateNetworkClientServer,

        /// <summary>
        /// APPLICATION PACKAGE AUTHORITY\Your pictures library
        /// </summary>
        CapabilityPicturesLibrary,

        /// <summary>
        /// APPLICATION PACKAGE AUTHORITY\Your videos library
        /// </summary>
        CapabilityVideosLibrary,

        /// <summary>
        /// APPLICATION PACKAGE AUTHORITY\Your music library
        /// </summary>
        CapabilityMusicLibrary,

        /// <summary>
        /// APPLICATION PACKAGE AUTHORITY\Your documents library
        /// </summary>
        CapabilityDocumentsLibrary,

        /// <summary>
        /// APPLICATION PACKAGE AUTHORITY\Your Windows credentials
        /// </summary>
        CapabilityEnterpriseAuthentication,

        /// <summary>
        /// APPLICATION PACKAGE AUTHORITY\Software and hardware certificates or a smart card
        /// </summary>
        CapabilitySharedUserCertificates,

        /// <summary>
        /// APPLICATION PACKAGE AUTHORITY\Removable storage
        /// </summary>
        CapabilityRemovableStorage,

        /// <summary>
        /// APPLICATION PACKAGE AUTHORITY\Your Appointments
        /// </summary>
        CapabilityAppointments,

        /// <summary>
        /// APPLICATION PACKAGE AUTHORITY\Your Contacts
        /// </summary>
        CapabilityContacts,

        /// <summary>
        /// APPLICATION PACKAGE AUTHORITY\Internet Explorer
        /// </summary>
        CapabilityInternetExplorer,

        /// <summary>
        /// Constrained Impersonation Capability
        /// </summary>
        CapabilityConstrainedImpersonation,

        /// <summary>
        /// OWNER RIGHTS
        /// </summary>
        OwnerRights,

        /// <summary>
        /// NT AUTHORITY\SELF
        /// </summary>
        Self,
    }

    /// <summary>
    /// Static methods to get some known SIDs.
    /// </summary>
    public static class KnownSids
    {
        /// <summary>
        /// NULL SID
        /// </summary>
        public static Sid Null { get { return GetKnownSid(KnownSidValue.Null); } }
        /// <summary>
        /// Everyone SID
        /// </summary>
        public static Sid World { get { return GetKnownSid(KnownSidValue.World); } }
        /// <summary>
        /// Local user SID
        /// </summary>
        public static Sid Local { get { return GetKnownSid(KnownSidValue.Local); } }
        /// <summary>
        /// CREATOR OWNER SID
        /// </summary>
        public static Sid CreatorOwner { get { return GetKnownSid(KnownSidValue.CreatorOwner); } }
        /// <summary>
        /// CREATOR GROUP SID
        /// </summary>
        public static Sid CreatorGroup { get { return GetKnownSid(KnownSidValue.CreatorGroup); } }
        /// <summary>
        /// Service SID
        /// </summary>
        public static Sid Service { get { return GetKnownSid(KnownSidValue.Service); } }
        /// <summary>
        /// ANONYMOUS LOGON SID
        /// </summary>
        public static Sid Anonymous { get { return GetKnownSid(KnownSidValue.Anonymous); } }
        /// <summary>
        /// Authenticated Users SID
        /// </summary>
        public static Sid AuthenticatedUsers { get { return GetKnownSid(KnownSidValue.AuthenticatedUsers); } }
        /// <summary>
        /// RESTRICTED SID
        /// </summary>
        public static Sid Restricted { get { return GetKnownSid(KnownSidValue.Restricted); } }
        /// <summary>
        /// LOCAL SYSTEM SID
        /// </summary>
        public static Sid LocalSystem { get { return GetKnownSid(KnownSidValue.LocalSystem); } }
        /// <summary>
        /// LOCAL SERVICE SID
        /// </summary>
        public static Sid LocalService { get { return GetKnownSid(KnownSidValue.LocalService); } }
        /// <summary>
        /// NETWORK SERVICE SID
        /// </summary>
        public static Sid NetworkService { get { return GetKnownSid(KnownSidValue.NetworkService); } }

        /// <summary>
        /// APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES SID
        /// </summary>
        public static Sid AllApplicationPackages { get { return GetKnownSid(KnownSidValue.AllApplicationPackages); } }

        /// <summary>
        /// APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES
        /// </summary>
        public static Sid AllRestrictedApplicationPackages { get { return GetKnownSid(KnownSidValue.AllRestrictedApplicationPackages); } }

        /// <summary>
        /// NT SERVICE\TrustedInstaller
        /// </summary>
        public static Sid TrustedInstaller { get { return GetKnownSid(KnownSidValue.TrustedInstaller); } }

        /// <summary>
        /// BUILTIN\Users
        /// </summary>
        public static Sid BuiltinUsers { get { return GetKnownSid(KnownSidValue.BuiltinUsers); } }

        /// <summary>
        /// BUILTIN\Administrators
        /// </summary>
        public static Sid BuiltinAdministrators { get { return GetKnownSid(KnownSidValue.BuiltinAdministrators); } }

        /// <summary>
        /// APPLICATION PACKAGE AUTHORITY\Your Internet connection
        /// </summary>
        public static Sid CapabilityInternetClient { get { return GetKnownSid(KnownSidValue.CapabilityInternetClient); } }

        /// <summary>
        /// APPLICATION PACKAGE AUTHORITY\Your Internet connection, including incoming connections from the Internet
        /// </summary>
        public static Sid CapabilityInternetClientServer { get { return GetKnownSid(KnownSidValue.CapabilityInternetClientServer); } }

        /// <summary>
        /// APPLICATION PACKAGE AUTHORITY\Your home or work networks
        /// </summary>
        public static Sid CapabilityPrivateNetworkClientServer { get {  return GetKnownSid(KnownSidValue.CapabilityPrivateNetworkClientServer); } }

        /// <summary>
        /// APPLICATION PACKAGE AUTHORITY\Your pictures library
        /// </summary>
        public static Sid CapabilityPicturesLibrary { get { return GetKnownSid(KnownSidValue.CapabilityPicturesLibrary); } }

        /// <summary>
        /// APPLICATION PACKAGE AUTHORITY\Your videos library
        /// </summary>
        public static Sid CapabilityVideosLibrary { get { return GetKnownSid(KnownSidValue.CapabilityVideosLibrary); } }

        /// <summary>
        /// APPLICATION PACKAGE AUTHORITY\Your music library
        /// </summary>
        public static Sid CapabilityMusicLibrary { get { return GetKnownSid(KnownSidValue.CapabilityMusicLibrary); } }

        /// <summary>
        /// APPLICATION PACKAGE AUTHORITY\Your documents library
        /// </summary>
        public static Sid CapabilityDocumentsLibrary { get { return GetKnownSid(KnownSidValue.CapabilityDocumentsLibrary); } }

        /// <summary>
        /// APPLICATION PACKAGE AUTHORITY\Your Windows credentials
        /// </summary>
        public static Sid CapabilityEnterpriseAuthentication { get { return GetKnownSid(KnownSidValue.CapabilityEnterpriseAuthentication); } }

        /// <summary>
        /// APPLICATION PACKAGE AUTHORITY\Software and hardware certificates or a smart card
        /// </summary>
        public static Sid CapabilitySharedUserCertificates { get { return GetKnownSid(KnownSidValue.CapabilitySharedUserCertificates); } }

        /// <summary>
        /// APPLICATION PACKAGE AUTHORITY\Removable storage
        /// </summary>
        public static Sid CapabilityRemovableStorage { get { return GetKnownSid(KnownSidValue.CapabilityRemovableStorage); } }

        /// <summary>
        /// APPLICATION PACKAGE AUTHORITY\Your Appointments
        /// </summary>
        public static Sid CapabilityAppointments { get { return GetKnownSid(KnownSidValue.CapabilityAppointments); } }

        /// <summary>
        /// APPLICATION PACKAGE AUTHORITY\Your Contacts
        /// </summary>
        public static Sid CapabilityContacts { get { return GetKnownSid(KnownSidValue.CapabilityContacts); } }

        /// <summary>
        /// APPLICATION PACKAGE AUTHORITY\Internet Explorer
        /// </summary>
        public static Sid CapabilityInternetExplorer {
            get { return GetKnownSid(KnownSidValue.CapabilityInternetExplorer); } }

        /// <summary>
        /// Constrained Impersonation Capability
        /// </summary>
        public static Sid CapabilityConstrainedImpersonation
        {
            get { return GetKnownSid(KnownSidValue.CapabilityConstrainedImpersonation); }
        }

        private static Sid GetCapabilitySid(params uint[] rids)
        {
            List<uint> capability = new List<uint>();
            capability.Add(3);
            capability.AddRange(rids);
            return new Sid(SecurityAuthority.Package, capability.ToArray());
        }

        /// <summary>
        /// Get a known SID based on a specific enumeration.
        /// </summary>
        /// <param name="sid">The enumerated sid value.</param>
        /// <returns></returns>
        public static Sid GetKnownSid(KnownSidValue sid)
        {
            switch (sid)
            {
                case KnownSidValue.Null: return new Sid(SecurityAuthority.Null, 0);
                case KnownSidValue.World: return new Sid(SecurityAuthority.World, 0);
                case KnownSidValue.Local: return new Sid(SecurityAuthority.Local, 0);
                case KnownSidValue.CreatorOwner: return new Sid(SecurityAuthority.Creator, 0);
                case KnownSidValue.CreatorGroup: return new Sid(SecurityAuthority.Creator, 1);
                case KnownSidValue.OwnerRights: return new Sid(SecurityAuthority.Creator, 4);
                case KnownSidValue.Service: return new Sid(SecurityAuthority.Nt, 6);
                case KnownSidValue.Anonymous: return new Sid(SecurityAuthority.Nt, 7);
                case KnownSidValue.AuthenticatedUsers: return new Sid(SecurityAuthority.Nt, 11);
                case KnownSidValue.Restricted: return new Sid(SecurityAuthority.Nt, 12);
                case KnownSidValue.LocalSystem: return new Sid(SecurityAuthority.Nt, 18);
                case KnownSidValue.LocalService: return new Sid(SecurityAuthority.Nt, 19);
                case KnownSidValue.NetworkService: return new Sid(SecurityAuthority.Nt, 20);
                case KnownSidValue.AllApplicationPackages: return new Sid(SecurityAuthority.Package, 2, 1);
                case KnownSidValue.AllRestrictedApplicationPackages: return new Sid(SecurityAuthority.Package, 2, 2);
                case KnownSidValue.TrustedInstaller: return NtSecurity.GetServiceSid("TrustedInstaller");
                case KnownSidValue.BuiltinUsers: return new Sid(SecurityAuthority.Nt, 32, 545);
                case KnownSidValue.BuiltinAdministrators: return new Sid(SecurityAuthority.Nt, 32, 544);
                case KnownSidValue.CapabilityInternetClient: return GetCapabilitySid(1);
                case KnownSidValue.CapabilityInternetClientServer: return GetCapabilitySid(2);
                case KnownSidValue.CapabilityPrivateNetworkClientServer: return GetCapabilitySid(3);
                case KnownSidValue.CapabilityPicturesLibrary: return GetCapabilitySid(4);
                case KnownSidValue.CapabilityVideosLibrary: return GetCapabilitySid(5);
                case KnownSidValue.CapabilityMusicLibrary: return GetCapabilitySid(6);
                case KnownSidValue.CapabilityDocumentsLibrary: return GetCapabilitySid(7);
                case KnownSidValue.CapabilityEnterpriseAuthentication: return GetCapabilitySid(8);
                case KnownSidValue.CapabilitySharedUserCertificates: return GetCapabilitySid(9);
                case KnownSidValue.CapabilityRemovableStorage: return GetCapabilitySid(10);
                case KnownSidValue.CapabilityAppointments: return GetCapabilitySid(11);
                case KnownSidValue.CapabilityContacts: return GetCapabilitySid(12);
                case KnownSidValue.CapabilityInternetExplorer: return GetCapabilitySid(4096);
                case KnownSidValue.CapabilityConstrainedImpersonation:
                    return GetCapabilitySid(1024, 1604681682, 535129537, 3273749797, 3666938095, 336295784, 2177615760, 2743807136, 2867270584);
                case KnownSidValue.Self: return new Sid(SecurityAuthority.Nt, 10);
                default:
                    throw new ArgumentException("Unknown SID type");
            }
        }
    }
}
