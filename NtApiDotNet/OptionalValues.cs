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
using System.Runtime.InteropServices;

namespace NtApiDotNet
{
    /// <summary>
    /// This class allows a function to specify an optional Guid
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public class OptionalGuid
    {
        /// <summary>
        /// Optional Guid
        /// </summary>
        public Guid Value;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="guid">The GUID to initialize</param>
        public OptionalGuid(Guid guid)
        {
            Value = guid;
        }

        /// <summary>
        /// Constructor
        /// </summary>
        public OptionalGuid() : this(Guid.Empty)
        {
        }

        /// <summary>
        /// Implicit conversion
        /// </summary>
        /// <param name="guid">The value</param>
        public static implicit operator OptionalGuid(Guid guid)
        {
            return new OptionalGuid(guid);
        }
    }

    /// <summary>
    /// This class allows a function to specify an optional uint16.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public class OptionalUInt16
    {
        /// <summary>
        /// Optional value
        /// </summary>
        public ushort Value;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="value">The value</param>
        public OptionalUInt16(ushort value)
        {
            Value = value;
        }

        /// <summary>
        /// Constructor
        /// </summary>
        public OptionalUInt16() : this(0)
        {
        }

        /// <summary>
        /// Implicit conversion
        /// </summary>
        /// <param name="value">The value</param>
        public static implicit operator OptionalUInt16(ushort value)
        {
            return new OptionalUInt16(value);
        }
    }

    /// <summary>
    /// This class allows a function to specify an optional int32.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public class OptionalInt32
    {
        /// <summary>
        /// Optional value
        /// </summary>
        public int Value;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="value">The value</param>
        public OptionalInt32(int value)
        {
            Value = value;
        }

        /// <summary>
        /// Constructor
        /// </summary>
        public OptionalInt32() : this(0)
        {
        }

        /// <summary>
        /// Implicit conversion
        /// </summary>
        /// <param name="value">The value</param>
        public static implicit operator OptionalInt32(int value)
        {
            return new OptionalInt32(value);
        }
    }

    /// <summary>
    /// This class allows a function to specify an optional int64.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public class OptionalInt64
    {
        /// <summary>
        /// Optional value
        /// </summary>
        public long Value;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="value">The value</param>
        public OptionalInt64(long value)
        {
            Value = value;
        }

        /// <summary>
        /// Constructor
        /// </summary>
        public OptionalInt64() : this(0)
        {
        }

        /// <summary>
        /// Implicit conversion
        /// </summary>
        /// <param name="value">The value</param>
        public static implicit operator OptionalInt64(long value)
        {
            return new OptionalInt64(value);
        }
    }

    /// <summary>
    /// This class allows a function to specify an optional length as a SizeT
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public class OptionalLength
    {
        /// <summary>
        /// Optional length
        /// </summary>
        public IntPtr Length;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="length">The length value</param>
        public OptionalLength(IntPtr length)
        {
            Length = length;
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="length">The length value</param>
        public OptionalLength(int length)
        {
            Length = new IntPtr(length);
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="length">The length value</param>
        public OptionalLength(long length)
        {
            Length = new IntPtr(length);
        }

        /// <summary>
        /// Implicit conversion
        /// </summary>
        /// <param name="length">The length value</param>
        public static implicit operator OptionalLength(int length)
        {
            return new OptionalLength(length);
        }
    }

    /// <summary>
    /// This class allows a function to specify an optional pointer.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public class OptionalPointer
    {
        /// <summary>
        /// Optional length
        /// </summary>
        public IntPtr Value;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="value">The value</param>
        public OptionalPointer(IntPtr value)
        {
            Value = value;
        }

        /// <summary>
        /// Constructor
        /// </summary>
        public OptionalPointer() : this(IntPtr.Zero)
        {
        }

        /// <summary>
        /// Implicit conversion
        /// </summary>
        /// <param name="value">The value</param>
        public static implicit operator OptionalPointer(IntPtr value)
        {
            return new OptionalPointer(value);
        }
    }

    /// <summary>
    /// Optional value.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public class OptionalTokenMandatoryPolicy
    {
        /// <summary>
        /// Optional value.
        /// </summary>
        public TokenMandatoryPolicy Value;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="value">The value</param>
        public OptionalTokenMandatoryPolicy(TokenMandatoryPolicy value)
        {
            Value = value;
        }

        /// <summary>
        /// Constructor
        /// </summary>
        public OptionalTokenMandatoryPolicy() : this(default)
        {
        }

        /// <summary>
        /// Implicit conversion
        /// </summary>
        /// <param name="value">The value.</param>
        public static implicit operator OptionalTokenMandatoryPolicy(TokenMandatoryPolicy value)
        {
            return new OptionalTokenMandatoryPolicy(value);
        }
    }

    /// <summary>
    /// Optional value.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public class OptionalTokenOwner
    {
        /// <summary>
        /// Optional value.
        /// </summary>
        public TokenOwner Value;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="value">The value</param>
        public OptionalTokenOwner(TokenOwner value)
        {
            Value = value;
        }

        /// <summary>
        /// Constructor
        /// </summary>
        public OptionalTokenOwner() : this(default)
        {
        }

        /// <summary>
        /// Implicit conversion
        /// </summary>
        /// <param name="value">The value.</param>
        public static implicit operator OptionalTokenOwner(TokenOwner value)
        {
            return new OptionalTokenOwner(value);
        }
    }

    /// <summary>
    /// Optional value.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public class OptionalTokenGroups
    {
        /// <summary>
        /// Optional value.
        /// </summary>
        public TokenGroups Value;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="value">The value</param>
        public OptionalTokenGroups(TokenGroups value)
        {
            Value = value;
        }

        /// <summary>
        /// Constructor
        /// </summary>
        public OptionalTokenGroups() : this(default)
        {
        }

        /// <summary>
        /// Implicit conversion
        /// </summary>
        /// <param name="value">The value.</param>
        public static implicit operator OptionalTokenGroups(TokenGroups value)
        {
            return new OptionalTokenGroups(value);
        }
    }

    /// <summary>
    /// Optional value.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public class OptionalTokenDefaultDacl
    {
        /// <summary>
        /// Optional value.
        /// </summary>
        public TokenDefaultDacl Value;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="value">The value</param>
        public OptionalTokenDefaultDacl(TokenDefaultDacl value)
        {
            Value = value;
        }

        /// <summary>
        /// Constructor
        /// </summary>
        public OptionalTokenDefaultDacl() : this(default)
        {
        }

        /// <summary>
        /// Implicit conversion
        /// </summary>
        /// <param name="value">The value.</param>
        public static implicit operator OptionalTokenDefaultDacl(TokenDefaultDacl value)
        {
            return new OptionalTokenDefaultDacl(value);
        }
    }
}
