//  Copyright 2019 Google Inc. All Rights Reserved.
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
using System.Linq;
using System.Runtime.InteropServices;

namespace NtApiDotNet
{
    /// <summary>
    /// Class to represent an Access Control List (ACL)
    /// </summary>
    public sealed class Acl : List<Ace>
    {
        #region Constructors
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="acl">Pointer to a raw ACL in memory</param>
        /// <param name="defaulted">True if the ACL was defaulted</param>
        public Acl(IntPtr acl, bool defaulted)
        {
            InitializeFromPointer(acl, defaulted);
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="acl">Buffer containing an ACL in memory</param>
        /// <param name="defaulted">True if the ACL was defaulted</param>
        public Acl(byte[] acl, bool defaulted)
        {
            using (var buffer = new SafeHGlobalBuffer(acl))
            {
                InitializeFromPointer(buffer.DangerousGetHandle(), defaulted);
            }
        }

        /// <summary>
        /// Constructor for a NULL ACL
        /// </summary>
        /// <param name="defaulted">True if the ACL was defaulted</param>
        public Acl(bool defaulted) : this(IntPtr.Zero, defaulted)
        {
            Defaulted = defaulted;
        }

        /// <summary>
        /// Constructor for an empty ACL
        /// </summary>
        public Acl() : this(new Ace[0], false)
        {
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="aces">List of ACEs to add to ACL</param>
        /// <param name="defaulted">True if the ACL was defaulted</param>
        public Acl(IEnumerable<Ace> aces, bool defaulted) : base(aces)
        {
            Defaulted = defaulted;
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="aces">List of ACEs to add to ACL</param>
        public Acl(IEnumerable<Ace> aces) : this(aces, false)
        {
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="sddl">An SDDL string to create the DACL from.</param>
        /// <remarks>The SDDL string should be of the form D:(...) or S:(...), if you specify
        /// both a DACL and a SACL then only the DACL will be used.</remarks>
        public Acl(string sddl)
        {
            SecurityDescriptor sd = new SecurityDescriptor(sddl);
            Acl acl = sd.Dacl ?? sd.Sacl
                ?? throw new ArgumentException("Must specify a DACL or a SACL", "sddl");
            Defaulted = acl.Defaulted;
            NullAcl = acl.NullAcl;
            Revision = acl.Revision;
            AddRange(acl);
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Convert the ACL to a byte array
        /// </summary>
        /// <returns>The ACL as a byte array</returns>
        public byte[] ToByteArray()
        {
            AclRevision revision;
            byte[] aces;
            using (var ace_stm = new MemoryStream())
            {
                using (var writer = new BinaryWriter(ace_stm))
                {
                    revision = Revision;
                    switch (revision)
                    {
                        case AclRevision.Revision:
                        case AclRevision.RevisionCompound:
                        case AclRevision.RevisionDS:
                            break;
                        default:
                            revision = AclRevision.Revision;
                            break;
                    }

                    foreach (Ace ace in this)
                    {
                        ace.Serialize(writer);
                        if (ace.IsObjectAce)
                        {
                            revision = AclRevision.RevisionDS;
                        }
                        else if (ace.Type == AceType.AllowedCompound 
                            && revision < AclRevision.RevisionCompound)
                        {
                            revision = AclRevision.RevisionCompound;
                        }
                    }
                }
                aces = ace_stm.ToArray();
            }

            using (var buffer = new SafeHGlobalBuffer(Marshal.SizeOf(typeof(AclStructure)) + aces.Length))
            {
                NtRtl.RtlCreateAcl(buffer, buffer.Length, revision).ToNtException();
                NtRtl.RtlAddAce(buffer, revision, uint.MaxValue, aces, aces.Length).ToNtException();
                return buffer.ToArray();
            }
        }

        /// <summary>
        /// Convert the ACL to a safe buffer
        /// </summary>
        /// <returns>The safe buffer</returns>
        public SafeHGlobalBuffer ToSafeBuffer()
        {
            if (!NullAcl)
            {
                return new SafeHGlobalBuffer(ToByteArray());
            }
            else
            {
                return SafeHGlobalBuffer.Null;
            }
        }

        /// <summary>
        /// Add an access allowed ace to the ACL
        /// </summary>
        /// <param name="mask">The ACE access mask</param>
        /// <param name="flags">The ACE flags</param>
        /// <param name="sid">The ACE SID</param>
        public void AddAccessAllowedAce(AccessMask mask, AceFlags flags, string sid)
        {
            Add(new Ace(AceType.Allowed, flags, mask, new Sid(sid)));
        }

        /// <summary>
        /// Add an access allowed ace to the ACL
        /// </summary>
        /// <param name="mask">The ACE access mask</param>
        /// <param name="sid">The ACE SID</param>
        public void AddAccessAllowedAce(AccessMask mask, string sid)
        {
            AddAccessAllowedAce(mask, AceFlags.None, sid);
        }

        /// <summary>
        /// Add an access allowed ace to the ACL
        /// </summary>
        /// <param name="mask">The ACE access mask</param>
        /// <param name="flags">The ACE flags</param>
        /// <param name="sid">The ACE SID</param>
        public void AddAccessAllowedAce(AccessMask mask, AceFlags flags, Sid sid)
        {
            Add(new Ace(AceType.Allowed, flags, mask, sid));
        }

        /// <summary>
        /// Add an access allowed ace to the ACL
        /// </summary>
        /// <param name="mask">The ACE access mask</param>
        /// <param name="sid">The ACE SID</param>
        public void AddAccessAllowedAce(AccessMask mask, Sid sid)
        {
            AddAccessAllowedAce(mask, AceFlags.None, sid);
        }

        /// <summary>
        /// Add an access denied ace to the ACL
        /// </summary>
        /// <param name="mask">The ACE access mask</param>
        /// <param name="flags">The ACE flags</param>
        /// <param name="sid">The ACE SID</param>
        public void AddAccessDeniedAce(AccessMask mask, AceFlags flags, string sid)
        {
            Add(new Ace(AceType.Denied, flags, mask, new Sid(sid)));
        }

        /// <summary>
        /// Add an access denied ace to the ACL
        /// </summary>
        /// <param name="mask">The ACE access mask</param>
        /// <param name="sid">The ACE SID</param>
        public void AddAccessDeniedAce(AccessMask mask, string sid)
        {
            AddAccessDeniedAce(mask, AceFlags.None, sid);
        }

        /// <summary>
        /// Add an access denied ace to the ACL
        /// </summary>
        /// <param name="mask">The ACE access mask</param>
        /// <param name="flags">The ACE flags</param>
        /// <param name="sid">The ACE SID</param>
        public void AddAccessDeniedAce(AccessMask mask, AceFlags flags, Sid sid)
        {
            Add(new Ace(AceType.Denied, flags, mask, sid));
        }

        /// <summary>
        /// Add an access denied ace to the ACL
        /// </summary>
        /// <param name="mask">The ACE access mask</param>
        /// <param name="sid">The ACE SID</param>
        public void AddAccessDeniedAce(AccessMask mask, Sid sid)
        {
            AddAccessDeniedAce(mask, AceFlags.None, sid);
        }

        /// <summary>
        /// Gets an indication if this ACL is canonical.
        /// </summary>
        /// <remarks>Canonical basically means that deny ACEs are before allow ACEs.</remarks>
        /// <returns>True if the ACL is canonical.</returns>
        public bool IsCanonical()
        {
            Acl acl = Canonicalize();
            if (acl.Count != Count)
            {
                return false;
            }

            for (int i = 0; i < acl.Count; ++i)
            {
                if (this[i] != acl[i])
                {
                    return false;
                }
            }
            return true;
        }

        /// <summary>
        /// Canonicalize the ACL (for use on DACLs only).
        /// </summary>
        /// <remarks>This isn't a general purpose algorithm, for example it doesn't worry much about object ordering.
        /// Also it can be lossy, if it doesn't understand an ACE type it will drop it.</remarks>
        /// <returns>The canonical ACL.</returns>
        public Acl Canonicalize()
        {
            List<Ace> access_denied = new List<Ace>();
            List<Ace> access_allowed = new List<Ace>();
            List<Ace> inherited = new List<Ace>();

            foreach (Ace ace in this)
            {
                if ((ace.Flags & AceFlags.Inherited) == AceFlags.Inherited)
                {
                    inherited.Add(ace);
                }
                else
                {
                    switch (ace.Type)
                    {
                        case AceType.Allowed:
                        case AceType.AllowedObject:
                            access_allowed.Add(ace);
                            break;
                        case AceType.Denied:
                        case AceType.DeniedObject:
                            access_denied.Add(ace);
                            break;
                    }
                }
            }

            Acl ret = new Acl();
            ret.AddRange(access_denied);
            ret.AddRange(access_allowed);
            ret.AddRange(inherited);
            return ret;
        }
        #endregion

        #region Public Properties
        /// <summary>
        /// Get or set whether the ACL was defaulted
        /// </summary>
        public bool Defaulted { get; set; }

        /// <summary>
        /// Get or set whether the ACL is NULL (no security)
        /// </summary>
        public bool NullAcl { get; set; }

        /// <summary>
        /// Get or set the protected flag.
        /// </summary>
        public bool Protected { get; set; }

        /// <summary>
        /// Get or set the auto-inherited flag.
        /// </summary>
        public bool AutoInherited { get; set; }

        /// <summary>
        /// Get or set the auto-inherited required flag.
        /// </summary>
        public bool AutoInheritReq { get; set; }

        /// <summary>
        /// Get or set the ACL revision
        /// </summary>
        public AclRevision Revision { get; set; }

        /// <summary>
        /// Indicates the ACL has at least one conditional ACE.
        /// </summary>
        public bool HasConditionalAce => this.Any(ace => ace.IsConditionalAce);

        /// <summary>
        /// Indicates the ACL has at least one object ACE.
        /// </summary>
        public bool HasObjectAce => this.Any(ace => ace.IsObjectAce);
        #endregion

        #region Private Members
        private static T GetAclInformation<T>(IntPtr acl, AclInformationClass info_class) where T : new()
        {
            using (var buffer = new SafeStructureInOutBuffer<T>())
            {
                NtRtl.RtlQueryInformationAcl(acl, buffer, buffer.Length, info_class).ToNtException();
                return buffer.Result;
            }
        }

        private void ParseAcl(IntPtr acl)
        {
            var size_info = GetAclInformation<AclSizeInformation>(acl, AclInformationClass.AclSizeInformation);
            using (var buffer = new SafeHGlobalBuffer(acl, size_info.AclBytesInUse, false))
            {
                using (var reader = new BinaryReader(new UnmanagedMemoryStream(buffer, 0, size_info.AclBytesInUse)))
                {
                    for (int i = 0; i < size_info.AceCount; ++i)
                    {
                        NtRtl.RtlGetAce(acl, i, out IntPtr ace).ToNtException();
                        reader.BaseStream.Position = ace.ToInt64() - acl.ToInt64();
                        Add(Ace.CreateAceFromReader(reader));
                    }
                }
            }
            Revision = GetAclInformation<AclRevisionInformation>(acl, AclInformationClass.AclRevisionInformation).AclRevision;
        }

        private void InitializeFromPointer(IntPtr acl, bool defaulted)
        {
            if (acl != IntPtr.Zero)
            {
                ParseAcl(acl);
            }
            else
            {
                NullAcl = true;
            }

            Defaulted = defaulted;
        }
        #endregion
    }
}
