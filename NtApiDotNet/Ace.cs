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

namespace NtApiDotNet
{
    /// <summary>
    /// Class to represent an Access Control Entry (ACE)
    /// </summary>
    public class Ace
    {
        private static bool IsObjectAceType(AceType type)
        {
            switch (type)
            {
                case AceType.AlarmCallbackObject:
                case AceType.AllowedCallbackObject:
                case AceType.AllowedObject:
                case AceType.AuditCallbackObject:
                case AceType.AuditObject:
                case AceType.DeniedCallbackObject:
                    return true;
            }
            return false;
        }

        /// <summary>
        /// Check if the ACE is an Object ACE
        /// </summary>
        public bool IsObjectAce
        {
            get
            {
                return IsObjectAceType(Type);
            }
        }

        private static bool IsCallbackAceType(AceType type)
        {
            switch (type)
            {
                case AceType.AlarmCallbackObject:
                case AceType.AllowedCallbackObject:
                case AceType.AuditCallbackObject:
                case AceType.DeniedCallbackObject:
                case AceType.AlarmCallback:
                case AceType.AllowedCallback:
                case AceType.AuditCallback:
                case AceType.DeniedCallback:
                    return true;
            }
            return false;
        }

        /// <summary>
        /// Check if the ACE is a callback ACE
        /// </summary>
        public bool IsCallbackAce
        {
            get
            {
                return IsCallbackAceType(Type);
            }
        }

        /// <summary>
        /// Check if ACE is a conditional ACE
        /// </summary>
        public bool IsConditionalAce
        {
            get
            {
                if (!IsCallbackAce)
                {
                    return false;
                }

                if (ApplicationData == null || ApplicationData.Length < 4)
                {
                    return false;
                }

                return BitConverter.ToUInt32(ApplicationData, 0) == 0x78747261;
            }
        }

        /// <summary>
        /// Check if ACE is an audit ACE.
        /// </summary>
        public bool IsAuditAce
        {
            get
            {
                switch (Type)
                {
                    case AceType.Alarm:
                    case AceType.AlarmCallback:
                    case AceType.AlarmCallbackObject:
                    case AceType.AlarmObject:
                    case AceType.Audit:
                    case AceType.AuditCallback:
                    case AceType.AuditCallbackObject:
                    case AceType.AuditObject:
                        return true;
                }
                return false;
            }
        }

        /// <summary>
        /// Check if ACE is a critical ACE.
        /// </summary>
        public bool IsCriticalAce => (Flags & AceFlags.Critical) != 0;

        internal Ace(AceType type)
        {
            Type = type;
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
            ace.Flags = (AceFlags)reader.ReadByte();
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

            ace.Sid = new Sid(reader);
            int bytes_used = (int)(reader.BaseStream.Position - current_position);
            ace.ApplicationData = reader.ReadAllBytes(ace_size - bytes_used);
            return ace;
        }

        internal void Serialize(BinaryWriter writer)
        {
            byte[] sid_data = Sid.ToArray();
            int total_length = 4 + 4 + sid_data.Length;
            if (ApplicationData != null)
            {
                total_length += ApplicationData.Length;
            }

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
            writer.Write((byte)Flags);
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
        }

        /// <summary>
        /// Get ACE type
        /// </summary>
        [Obsolete("Use Type property")]
        public AceType AceType { get { return Type; } set { Type = value; } }

        /// <summary>
        /// Get ACE flags
        /// </summary>
        [Obsolete("Use Flags property")]
        public AceFlags AceFlags { get { return Flags; } set { Flags = value; } }

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
                    }
                }
            }
        }

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
        /// Compare ACE to another object.
        /// </summary>
        /// <param name="obj">The other object.</param>
        /// <returns>True if the other object equals this ACE</returns>
        public override bool Equals(object obj)
        {
            if (object.ReferenceEquals(obj, this))
            {
                return true;
            }

            Ace ace = obj as Ace;
            if (ace == null)
            {
                return false;
            }

            return ace.Type == Type && ace.Flags == Flags && ace.Sid == Sid && ace.Mask == Mask
                && ace.ObjectType == ObjectType && ace.InheritedObjectType == InheritedObjectType;
        }

        /// <summary>
        /// Get hash code.
        /// </summary>
        /// <returns>The hash code</returns>
        public override int GetHashCode()
        {
            return Type.GetHashCode() ^ Flags.GetHashCode() ^ Mask.GetHashCode() ^ Sid.GetHashCode() ^ ObjectType.GetHashCode() ^ InheritedObjectType.GetHashCode();
        }

        /// <summary>
        /// Equality operator
        /// </summary>
        /// <param name="a">Left ACE</param>
        /// <param name="b">Right ACE</param>
        /// <returns>True if the ACEs are equal</returns>
        public static bool operator ==(Ace a, Ace b)
        {
            if (object.ReferenceEquals(a, b))
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
    }
}
