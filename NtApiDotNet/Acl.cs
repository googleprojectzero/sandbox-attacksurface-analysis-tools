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
        /// <remarks>Canonical means that deny ACEs are before allow ACEs.</remarks>
        /// <param name="dacl">True to canonicalize a DACL, otherwise a SACL.</param>
        /// <returns>True if the ACL is canonical.</returns>
        public bool IsCanonical(bool dacl)
        {
            Acl acl = Clone();
            acl.Canonicalize(dacl);
            if (acl.Count != Count)
            {
                return false;
            }

            for (int i = 0; i < acl.Count; ++i)
            {
                if (!ReferenceEquals(this[i], acl[i]))
                {
                    return false;
                }
            }
            return true;
        }

        /// <summary>
        /// Gets an indication if this DACL is canonical.
        /// </summary>
        /// <remarks>Canonical basically means that deny ACEs are before allow ACEs.</remarks>
        /// <returns>True if the ACL is canonical.</returns>
        [Obsolete("Use IsCanonical with flag")]
        public bool IsCanonical()
        {
            return IsCanonical(true);
        }

        /// <summary>
        /// Canonicalize the ACL.
        /// </summary>
        /// <param name="dacl">True to canonicalize a DACL, otherwise a SACL.</param>
        public void Canonicalize(bool dacl)
        {
            var aces = dacl ? this.Select(GetDaclCanonicalLevel) : this.Select(GetSaclCanonicalLevel);
            Ace[] ace_array = aces.OrderBy(t => t.Item1).Select(t => t.Item2).ToArray();
            Clear();
            AddRange(ace_array);
        }

        /// <summary>
        /// Canonicalize the ACL (for use on DACLs only).
        /// </summary>
        /// <returns>The canonical ACL.</returns>
        [Obsolete("Use Canonicalize with flag")]
        public Acl Canonicalize()
        {
            Acl acl = Clone();
            acl.Canonicalize(true);
            return acl;
        }

        /// <summary>
        /// Find the first ACE with a specified type.
        /// </summary>
        /// <param name="type">The type to find.</param>
        /// <param name="include_inherit_only">True to include inherit only ACEs.</param>
        /// <returns>The found ace. Returns null if not found.</returns>
        public Ace FindAce(AceType type, bool include_inherit_only)
        {
            if (include_inherit_only)
                return Find(a => a.Type == type);
            return Find(a => a.Type == type && !a.IsInheritOnly);
        }

        /// <summary>
        /// Find the first ACE with a specified type. Includes InheritOnly ACEs.
        /// </summary>
        /// <param name="type">The type to find.</param>
        /// <returns>The found ace. Returns null if not found.</returns>
        public Ace FindAce(AceType type)
        {
            return FindAce(type, true);
        }

        /// <summary>
        /// Find the all ACE with a specified type.
        /// </summary>
        /// <param name="type">The type to find.</param>
        /// <param name="include_inherit_only">True to include inherit only ACEs.</param>
        /// <returns>The found aces.</returns>
        public IEnumerable<Ace> FindAllAce(AceType type, bool include_inherit_only)
        {
            if (include_inherit_only)
                return FindAll(a => a.Type == type);
            return FindAll(a => a.Type == type && !a.IsInheritOnly);
        }

        /// <summary>
        /// Find the all ACE with a specified type. Includes InheritOnly ACEs.
        /// </summary>
        /// <param name="type">The type to find.</param>
        /// <returns>The found aces.</returns>
        public IEnumerable<Ace> FindAllAce(AceType type)
        {
            return FindAllAce(type, true);
        }

        /// <summary>
        /// Find the last ACE with a specified type.
        /// </summary>
        /// <param name="type">The type to find.</param>
        /// <returns>The found ace. Returns null if not found.</returns>
        public Ace FindLastAce(AceType type)
        {
            return FindLast(a => a.Type == type);
        }

        /// <summary>
        /// Clone the ACL. Also clones all ACEs.
        /// </summary>
        /// <returns>The cloned ACL.</returns>
        public Acl Clone()
        {
            return new Acl(this.Select(a => a.Clone()))
            {
                Defaulted = Defaulted,
                NullAcl = NullAcl,
                Protected = Protected,
                AutoInherited = AutoInherited,
                AutoInheritReq = AutoInheritReq,
                Revision = Revision
            };
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

        private const int ACE_LEVEL_0 = 0;
        private const int ACE_LEVEL_1 = 0x10000;
        private const int ACE_LEVEL_2 = 0x20000;
        private const int ACE_LEVEL_3 = 0x30000;
        private const int ACE_LEVEL_4 = 0x40000;
        private const int ACE_LEVEL_INHERITED = 0x50000;

        private Tuple<int, Ace> GetSaclCanonicalLevel(Ace ace, int index)
        {
            int level;
            if (ace.Flags.HasFlagSet(AceFlags.Inherited))
            {
                level = ACE_LEVEL_INHERITED;
            }
            else
            {
                switch (ace.Type)
                {
                    case AceType.Audit:
                    case AceType.AuditCallback:
                    case AceType.Alarm:
                    case AceType.AlarmCallback:
                        level = ACE_LEVEL_0;
                        break;
                    case AceType.AuditObject:
                    case AceType.AuditCallbackObject:
                    case AceType.AlarmObject:
                    case AceType.AlarmCallbackObject:
                        level = ACE_LEVEL_1;
                        break;
                    default:
                        level = ACE_LEVEL_2;
                        break;
                }
            }

            return Tuple.Create(level + index, ace);
        }

        private Tuple<int, Ace> GetDaclCanonicalLevel(Ace ace, int index)
        {
            int level;
            if (ace.Flags.HasFlagSet(AceFlags.Inherited))
            {
                level = ACE_LEVEL_INHERITED;
            }
            else
            {
                switch (ace.Type)
                {
                    case AceType.Allowed:
                    case AceType.AllowedCallback:
                    case AceType.AllowedCompound:
                        level = ACE_LEVEL_2;
                        break;
                    case AceType.AllowedObject:
                    case AceType.AllowedCallbackObject:
                        level = ACE_LEVEL_3;
                        break;
                    case AceType.Denied:
                    case AceType.DeniedCallback:
                        level = ACE_LEVEL_0;
                        break;
                    case AceType.DeniedObject:
                    case AceType.DeniedCallbackObject:
                        level = ACE_LEVEL_1;
                        break;
                    default:
                        level = ACE_LEVEL_4;
                        break;
                }
            }

            return Tuple.Create(level + index, ace);
        }

        #endregion
    }
}
