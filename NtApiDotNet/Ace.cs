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
using System.IO;
using System.Runtime.InteropServices;

namespace NtApiDotNet
{
    /// <summary>
    /// Class to represent an Access Control Entry (ACE)
    /// </summary>
    public class Ace
    {
        #region Public Properties

        /// <summary>
        /// Check if the ACE is an allowed ACE.
        /// </summary>
        public bool IsAllowedAce => NtSecurity.IsAllowedAceType(Type);

        /// <summary>
        /// Check if the ACE is a denied ACE.
        /// </summary>
        public bool IsDeniedAce => NtSecurity.IsDeniedAceType(Type);

        /// <summary>
        /// Check if the ACE is an Object ACE
        /// </summary>
        public bool IsObjectAce => NtSecurity.IsObjectAceType(Type);

        /// <summary>
        /// Check if the ACE is a callback ACE
        /// </summary>
        public bool IsCallbackAce => NtSecurity.IsCallbackAceType(Type);

        /// <summary>
        /// Check if ACE is a conditional ACE
        /// </summary>
        public bool IsConditionalAce
        {
            get
            {
                if (!IsCallbackAce && !IsAccessFilterAce)
                {
                    return false;
                }

                if (ApplicationData == null || ApplicationData.Length < 4)
                {
                    return false;
                }

                return BitConverter.ToUInt32(ApplicationData, 0) == 0x78747261; // xtra.
            }
        }

        /// <summary>
        /// Check if ACE is a resource attribute ACE.
        /// </summary>
        public bool IsResourceAttributeAce => Type == AceType.ResourceAttribute;

        /// <summary>
        /// Check if ACE is a mandatory label ACE.
        /// </summary>
        public bool IsMandatoryLabel => Type == AceType.MandatoryLabel;

        /// <summary>
        /// Check if ACE is a compound ACE.
        /// </summary>
        public bool IsCompoundAce => Type == AceType.AllowedCompound;

        /// <summary>
        /// Check if ACE is an audit ACE.
        /// </summary>
        public bool IsAuditAce => NtSecurity.IsAuditAceType(Type);

        /// <summary>
        /// Check if ACE is an access filter ACE.
        /// </summary>
        public bool IsAccessFilterAce => Type == AceType.AccessFilter;

        /// <summary>
        /// Check if ACE is a process trust label ACE.
        /// </summary>
        public bool IsProcessTrustLabelAce => Type == AceType.ProcessTrustLabel;

        /// <summary>
        /// Check if ACE is a critical ACE.
        /// </summary>
        public bool IsCriticalAce => Flags.HasFlag(AceFlags.Critical);

        /// <summary>
        /// Check if ACE is inherit only.
        /// </summary>
        public bool IsInheritOnly => Flags.HasFlag(AceFlags.InheritOnly);

        /// <summary>
        /// Check if ACE is inherited by objects.
        /// </summary>
        public bool IsObjectInherit => Flags.HasFlag(AceFlags.ObjectInherit);

        /// <summary>
        /// Check if ACE is inherited by objects.
        /// </summary>
        public bool IsContainerInherit => Flags.HasFlag(AceFlags.ContainerInherit);

        /// <summary>
        /// Get ACE type
        /// </summary>
        public AceType Type { get; set; }

        /// <summary>
        /// Get ACE flags
        /// </summary>
        public AceFlags Flags { get; set; }

        /// <summary>
        /// Get ACE access mask
        /// </summary>
        public AccessMask Mask { get; set; }

        /// <summary>
        /// Get ACE Security Identifier
        /// </summary>
        public Sid Sid { get; set; }

        /// <summary>
        /// The type of compound ACE. When serialized always set to Impersonate.
        /// </summary>
        public CompoundAceType CompoundAceType { get; private set; }

        /// <summary>
        /// Get the client SID in a compound ACE.
        /// </summary>
        public Sid ServerSid { get; set; }

        /// <summary>
        /// Get optional Object Type
        /// </summary>
        public Guid? ObjectType { get; set; }

        /// <summary>
        /// Get optional Inherited Object Type
        /// </summary>
        public Guid? InheritedObjectType { get; set; }

        /// <summary>
        /// Optional application data.
        /// </summary>
        public byte[] ApplicationData { get; set; }

        /// <summary>
        /// Get conditional check if a conditional ace.
        /// </summary>
        public string Condition
        {
            get
            {
                if (IsConditionalAce)
                {
                    return NtSecurity.ConditionalAceToString(ApplicationData);
                }
                return string.Empty;
            }

            set
            {
                if (string.IsNullOrWhiteSpace(value))
                {
                    ApplicationData = new byte[0];
                    switch (Type)
                    {
                        case AceType.AllowedCallback:
                            Type = AceType.Allowed;
                            break;
                        case AceType.DeniedCallback:
                            Type = AceType.Denied;
                            break;
                        case AceType.AllowedCallbackObject:
                            Type = AceType.AllowedObject;
                            break;
                        case AceType.DeniedCallbackObject:
                            Type = AceType.DeniedObject;
                            break;
                        case AceType.AlarmCallback:
                            Type = AceType.Alarm;
                            break;
                        case AceType.AuditCallback:
                            Type = AceType.Audit;
                            break;
                        case AceType.AlarmCallbackObject:
                            Type = AceType.AlarmObject;
                            break;
                        case AceType.AuditCallbackObject:
                            Type = AceType.AuditObject;
                            break;
                    }
                }
                else
                {
                    ApplicationData = NtSecurity.StringToConditionalAce(value);
                    switch (Type)
                    {
                        case AceType.Allowed:
                            Type = AceType.AllowedCallback;
                            break;
                        case AceType.Denied:
                            Type = AceType.DeniedCallback;
                            break;
                        case AceType.Alarm:
                            Type = AceType.AlarmCallback;
                            break;
                        case AceType.Audit:
                            Type = AceType.AuditCallback;
                            break;
                        case AceType.AllowedObject:
                            Type = AceType.AllowedCallbackObject;
                            break;
                        case AceType.DeniedObject:
                            Type = AceType.DeniedCallbackObject;
                            break;
                        case AceType.AlarmObject:
                            Type = AceType.AlarmCallbackObject;
                            break;
                        case AceType.AuditObject:
                            Type = AceType.AuditCallbackObject;
                            break;
                    }
                }
            }
        }

        /// <summary>
        /// Get or set resource attribute.
        /// </summary>
        public ClaimSecurityAttribute ResourceAttribute
        {
            get
            {
                if (!IsResourceAttributeAce || ApplicationData == null || ApplicationData.Length == 0)
                    return null;
                return new ClaimSecurityAttribute(ApplicationData);
            }

            set
            {
                if (!IsResourceAttributeAce)
                    throw new ArgumentException("Only supported for Resource Attribute ACEs.");
                ApplicationData = value.ToBuilder().MarshalAttribute();
            }
        }

        #endregion

        #region Constructors

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="type">ACE type</param>
        /// <param name="flags">ACE flags</param>
        /// <param name="mask">ACE access mask</param>
        /// <param name="sid">ACE sid</param>
        public Ace(AceType type, AceFlags flags, AccessMask mask, Sid sid)
        {
            Type = type;
            Flags = flags;
            Mask = mask;
            Sid = sid;
            ApplicationData = new byte[0];
        }

        internal Ace(AceType type)
        {
            Type = type;
        }
        #endregion

        #region Internal Members

        internal static Ace Parse(IntPtr ace_ptr)
        {
            AceHeader header = (AceHeader)Marshal.PtrToStructure(ace_ptr, typeof(AceHeader));
            using (var buffer = new SafeHGlobalBuffer(ace_ptr, header.AceSize, false))
            {
                using (var reader = new BinaryReader(new UnmanagedMemoryStream(buffer, 0, header.AceSize)))
                {
                    return CreateAceFromReader(reader);
                }
            }
        }

        internal static Ace CreateAceFromReader(BinaryReader reader)
        {
            long current_position = reader.BaseStream.Position;
            AceType type = (AceType)reader.ReadByte();
            Ace ace;
            switch (type)
            {
                case AceType.MandatoryLabel:
                    ace = new MandatoryLabelAce();
                    break;
                default:
                    ace = new Ace(type);
                    break;
            }
            ace.Flags = MapToFlags(type, reader.ReadByte());
            int ace_size = reader.ReadUInt16();
            ace.Mask = reader.ReadUInt32();
            if (ace.IsObjectAce)
            {
                ObjectAceFlags flags = (ObjectAceFlags)reader.ReadUInt32();
                if ((flags & ObjectAceFlags.ObjectTypePresent) != 0)
                {
                    ace.ObjectType = new Guid(reader.ReadAllBytes(16));
                }
                if ((flags & ObjectAceFlags.InheritedObjectTypePresent) != 0)
                {
                    ace.InheritedObjectType = new Guid(reader.ReadAllBytes(16));
                }
            }

            if (type == AceType.AllowedCompound)
            {
                // Read out compound ace type.
                ace.CompoundAceType = (CompoundAceType)reader.ReadUInt16();
                // Reserved.
                reader.ReadInt16();
                ace.ServerSid = new Sid(reader);
            }
            ace.Sid = new Sid(reader);
            int bytes_used = (int)(reader.BaseStream.Position - current_position);
            ace.ApplicationData = reader.ReadAllBytes(ace_size - bytes_used);
            return ace;
        }

        internal void Serialize(BinaryWriter writer)
        {
            byte[] sid_data = Sid.ToArray();
            if (Type == AceType.AllowedCompound)
            {
                MemoryStream stm = new MemoryStream();
                BinaryWriter sidwriter = new BinaryWriter(stm);
                sidwriter.Write((int)CompoundAceType.Impersonation);
                sidwriter.Write(ServerSid.ToArray());
                sidwriter.Write(sid_data);
                sid_data = stm.ToArray();
            }

            int total_length = 4 + 4 + sid_data.Length;
            if (ApplicationData != null)
            {
                total_length += ApplicationData.Length;
            }

            // Add a round up to 4 byte alignment.
            int padding = 4 - (total_length % 4);
            if (padding == 4)
            {
                padding = 0;
            }

            total_length += padding;

            ObjectAceFlags flags = ObjectAceFlags.None;
            if (IsObjectAce)
            {
                // For Flags
                total_length += 4;
                if (ObjectType.HasValue)
                {
                    total_length += 16;
                    flags |= ObjectAceFlags.ObjectTypePresent;
                }
                if (InheritedObjectType.HasValue)
                {
                    total_length += 16;
                    flags |= ObjectAceFlags.InheritedObjectTypePresent;
                }
            }
            if (total_length > ushort.MaxValue)
            {
                throw new ArgumentOutOfRangeException("Total ACE length greater than maximum");
            }

            writer.Write((byte)Type);
            writer.Write(MapFromFlags(Type, Flags));
            writer.Write((ushort)total_length);
            writer.Write(Mask.Access);
            if (IsObjectAce)
            {
                writer.Write((uint)flags);
                if (ObjectType.HasValue)
                {
                    writer.Write(ObjectType.Value.ToByteArray());
                }
                if (InheritedObjectType.HasValue)
                {
                    writer.Write(InheritedObjectType.Value.ToByteArray());
                }
            }
            writer.Write(sid_data);
            writer.Write(ApplicationData ?? new byte[0]);
            if (padding != 0)
            {
                writer.Write(new byte[padding]);
            }
        }

        #endregion

        #region Public Methods
        /// <summary>
        /// Convert ACE to a string
        /// </summary>
        /// <returns>The ACE as a string</returns>
        public override string ToString()
        {
            return $"Type {Type} - Flags {Flags} - Mask {Mask:X08} - Sid {Sid}";
        }

        /// <summary>
        /// Convert ACE to a string
        /// </summary>
        /// <param name="access_rights_type">An enumeration type to format the access mask</param>
        /// <param name="resolve_sid">True to try and resolve SID to a name</param>
        /// <returns>The ACE as a string</returns>
        public string ToString(Type access_rights_type, bool resolve_sid)
        {
            object mask = Enum.ToObject(access_rights_type, Mask);
            string account = Sid.ToString();
            if (resolve_sid)
            {
                account = NtSecurity.LookupAccountSid(Sid) ?? Sid.ToString();
            }
            return $"Type {Type} - Flags {Flags} - Mask {mask} - Sid {account}";
        }

        /// <summary>
        /// Clone this ACE.
        /// </summary>
        /// <returns>The cloned ACE.</returns>
        public Ace Clone()
        {
            Ace ace = (Ace)this.MemberwiseClone();
            if (ace.ApplicationData != null)
            {
                ace.ApplicationData = (byte[])ace.ApplicationData.Clone();
            }
            return ace;
        }

        /// <summary>
        /// Compare ACE to another object.
        /// </summary>
        /// <param name="obj">The other object.</param>
        /// <returns>True if the other object equals this ACE</returns>
        public override bool Equals(object obj)
        {
            if (ReferenceEquals(obj, this))
            {
                return true;
            }

            Ace ace = obj as Ace;
            if (ace == null)
            {
                return false;
            }

            return ace.Type == Type && ace.Flags == Flags && ace.Sid == Sid && ace.Mask == Mask
                && ace.ObjectType == ObjectType && ace.InheritedObjectType == InheritedObjectType
                && ace.ServerSid == ServerSid && NtObjectUtils.EqualByteArray(ApplicationData, ace.ApplicationData);
        }

        /// <summary>
        /// Get hash code.
        /// </summary>
        /// <returns>The hash code</returns>
        public override int GetHashCode()
        {
            return Type.GetHashCode() ^ Flags.GetHashCode() ^ Mask.GetHashCode()
                ^ Sid.GetHashCode() ^ ObjectType.GetHashCode() ^ InheritedObjectType.GetHashCode()
                ^ ServerSid?.GetHashCode() ?? 0 ^ NtObjectUtils.GetHashCodeByteArray(ApplicationData);
        }
        #endregion

        #region Static Methods
        /// <summary>
        /// Equality operator
        /// </summary>
        /// <param name="a">Left ACE</param>
        /// <param name="b">Right ACE</param>
        /// <returns>True if the ACEs are equal</returns>
        public static bool operator ==(Ace a, Ace b)
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
        /// Not Equal operator
        /// </summary>
        /// <param name="a">Left ACE</param>
        /// <param name="b">Right ACE</param>
        /// <returns>True if the ACEs are not equal</returns>
        public static bool operator !=(Ace a, Ace b)
        {
            return !(a == b);
        }
        #endregion

        #region Private Members
        private static AceFlags MapToFlags(AceType type, byte flags)
        {
            AceFlags ret = (AceFlags)flags;
            if (type == AceType.AccessFilter && ret.HasFlagSet(AceFlags.SuccessfulAccess))
            {
                ret &= ~AceFlags.SuccessfulAccess;
                ret |= AceFlags.TrustProtected;
            }
            return ret;
        }

        private static byte MapFromFlags(AceType type, AceFlags flags)
        {
            byte ret = (byte)flags;
            if (type == AceType.AccessFilter && flags.HasFlagSet(AceFlags.TrustProtected))
            {
                ret |= 0x40;
            }
            return ret;
        }

        #endregion
    }
}
