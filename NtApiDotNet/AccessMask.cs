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
using System.Runtime.InteropServices;

namespace NtApiDotNet
{
    /// <summary>
    /// Structure for an NT access mask.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct AccessMask : IFormattable, IEquatable<AccessMask>, IComparable<AccessMask>
    {
        /// <summary>
        /// The access mask's access bits.
        /// </summary>
        public uint Access;

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="access">Access bits to use</param>
        public AccessMask(uint access)
        {
            Access = access;
        }

        /// <summary>
        /// Implicit conversion from Int32.
        /// </summary>
        /// <param name="access">The access enumeration.</param>
        public static implicit operator AccessMask(int access)
        {
            return new AccessMask((uint)access);
        }

        /// <summary>
        /// Implicit conversion from UInt32.
        /// </summary>
        /// <param name="access">The access enumeration.</param>
        public static implicit operator AccessMask(uint access)
        {
            return new AccessMask(access);
        }

        /// <summary>
        /// Implicit conversion from enumerations.
        /// </summary>
        /// <param name="access">The access enumeration.</param>
        public static implicit operator AccessMask(Enum access)
        {
            return new AccessMask(((IConvertible)access).ToUInt32(null));
        }

        /// <summary>
        /// Convert access mask to a generic access object.
        /// </summary>
        /// <returns>The generic access mask</returns>
        public GenericAccessRights ToGenericAccess()
        {
            return (GenericAccessRights)Access;
        }

        /// <summary>
        /// Convert access mask to a mandatory label policy
        /// </summary>
        /// <returns>The mandatory label policy</returns>
        public MandatoryLabelPolicy ToMandatoryLabelPolicy()
        {
            return (MandatoryLabelPolicy)Access;
        }

        /// <summary>
        /// Convert to a specific access right.
        /// </summary>
        /// <typeparam name="A">The specific access right.</typeparam>
        /// <returns>The converted value.</returns>
        public A ToSpecificAccess<A>() where A : Enum
        {
            return (A)(object)Access;
        }

        /// <summary>
        /// Convert to a specific access right.
        /// </summary>
        /// <param name="enum_type">The type of enumeration to convert to.</param>
        /// <returns>The converted value.</returns>
        public Enum ToSpecificAccess(Type enum_type)
        {
            if (!enum_type.IsEnum)
                throw new ArgumentException("Type must be an Enum", "enum_type");
            return (Enum)Enum.ToObject(enum_type, Access);
        }

        /// <summary>
        /// Get whether this access mask is empty (i.e. it's 0)
        /// </summary>
        public bool IsEmpty => Access == 0;

        /// <summary>
        /// Get whether this access mask has no access rights, i.e. not empty.
        /// </summary>
        public bool HasAccess => !IsEmpty;

        /// <summary>
        /// Get whether this access mask has generic access rights.
        /// </summary>
        public bool HasGenericAccess => (Access & 0xF0000000) != 0;

        /// <summary>
        /// Get whether the current access mask is granted specific permissions.
        /// </summary>
        /// <param name="mask">The access mask to check</param>
        /// <returns>True one or more access granted.</returns>
        public bool IsAccessGranted(AccessMask mask) => (Access & mask.Access) != 0;

        /// <summary>
        /// Get whether the current access mask is granted all specific permissions.
        /// </summary>
        /// <param name="mask">The access mask to check</param>
        /// <returns>True access all is granted.</returns>
        public bool IsAllAccessGranted(AccessMask mask) => (Access & mask.Access) == mask.Access;

        /// <summary>
        /// Bitwise AND operator.
        /// </summary>
        /// <param name="mask1">Access mask 1</param>
        /// <param name="mask2">Access mask 2</param>
        /// <returns>The new access mask.</returns>
        public static AccessMask operator &(AccessMask mask1, AccessMask mask2)
        {
            return new AccessMask(mask1.Access & mask2.Access);
        }

        /// <summary>
        /// Bitwise OR operator.
        /// </summary>
        /// <param name="mask1">Access mask 1</param>
        /// <param name="mask2">Access mask 2</param>
        /// <returns>The new access mask.</returns>
        public static AccessMask operator |(AccessMask mask1, AccessMask mask2)
        {
            return new AccessMask(mask1.Access | mask2.Access);
        }

        /// <summary>
        /// Bitwise AND operator.
        /// </summary>
        /// <param name="mask1">Access mask 1</param>
        /// <param name="mask2">Access mask 2</param>
        /// <returns>The new access mask.</returns>
        public static AccessMask operator &(AccessMask mask1, uint mask2)
        {
            return new AccessMask(mask1.Access & mask2);
        }

        /// <summary>
        /// Bitwise OR operator.
        /// </summary>
        /// <param name="mask1">Access mask 1</param>
        /// <param name="mask2">Access mask 2</param>
        /// <returns>The new access mask.</returns>
        public static AccessMask operator |(AccessMask mask1, uint mask2)
        {
            return new AccessMask(mask1.Access | mask2);
        }

        /// <summary>
        /// Equality operator.
        /// </summary>
        /// <param name="mask1">Access mask 1</param>
        /// <param name="mask2">Access mask 2</param>
        /// <returns>True if equal.</returns>
        public static bool operator ==(AccessMask mask1, AccessMask mask2)
        {
            return mask1.Access == mask2.Access;
        }

        /// <summary>
        /// Inequality operator.
        /// </summary>
        /// <param name="mask1">Access mask 1</param>
        /// <param name="mask2">Access mask 2</param>
        /// <returns>True if equal.</returns>
        public static bool operator !=(AccessMask mask1, AccessMask mask2)
        {
            return mask1.Access != mask2.Access;
        }

        /// <summary>
        /// Bitwise NOT operator.
        /// </summary>
        /// <param name="mask1">Access mask 1</param>
        /// <returns>The new access mask.</returns>
        public static AccessMask operator ~(AccessMask mask1)
        {
            return new AccessMask(~mask1.Access);
        }

        /// <summary>
        /// Overridden GetHashCode.
        /// </summary>
        /// <returns>The hash code.</returns>
        public override int GetHashCode()
        {
            return Access.GetHashCode();
        }

        /// <summary>
        /// Overridden Equals.
        /// </summary>
        /// <param name="obj">The object to compare against.</param>
        /// <returns>True if equal.</returns>
        public override bool Equals(object obj)
        {
            if (!(obj is AccessMask))
            {
                return false;
            }
            AccessMask mask = (AccessMask)obj;
            return Access == mask.Access;
        }

        /// <summary>
        /// Get an empty access mask.
        /// </summary>
        public static AccessMask Empty { get { return new AccessMask(); } }

        /// <summary>
        /// Overridden ToString method.
        /// </summary>
        /// <returns>The access mask.</returns>
        public override string ToString()
        {
            return ToString("X08");
        }

        /// <summary>
        /// ToString method.
        /// </summary>
        /// <param name="format">Format code for the access mask.</param>
        /// <returns>The formatting string.</returns>
        public string ToString(string format)
        {
            return ToString(format, null);
        }

        /// <summary>
        /// ToString method.
        /// </summary>
        /// <param name="format">Format code for the access mask.</param>
        /// <param name="formatProvider">The format provider.</param>
        /// <returns>The formatting string.</returns>
        public string ToString(string format, IFormatProvider formatProvider)
        {
            return Access.ToString(format, formatProvider);
        }

        bool IEquatable<AccessMask>.Equals(AccessMask other)
        {
            return Access == other.Access;
        }

        int IComparable<AccessMask>.CompareTo(AccessMask other)
        {
            return Access.CompareTo(other.Access);
        }
    }
}
