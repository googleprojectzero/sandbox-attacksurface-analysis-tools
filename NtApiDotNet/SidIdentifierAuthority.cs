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
using System.Linq;
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
        private readonly byte[] _value;

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
        /// Construct from an Int64.
        /// </summary>
        /// <param name="authority">The authority as an Int64.</param>
        public SidIdentifierAuthority(long authority)
        {
            _value = BitConverter.GetBytes(authority).Take(6).Reverse().ToArray();
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
            return Equals(new SidIdentifierAuthority(authority));
        }

        /// <summary>
        /// Convert authority to a 64 bit integer.
        /// </summary>
        /// <returns>The authority as a 64 bit integer.</returns>
        public long ToInt64()
        {
            byte[] temp = _value.Reverse().Concat(new byte[2]).ToArray();
            return BitConverter.ToInt64(temp, 0);
        }

        /// <summary>
        /// Overridden ToString method.
        /// </summary>
        /// <returns>The security authority as a string.</returns>
        public override string ToString()
        {
            long i = ToInt64();
            if (i < byte.MaxValue && Enum.IsDefined(typeof(SecurityAuthority), (byte)i))
            {
                return Enum.GetName(typeof(SecurityAuthority), (byte)i);
            }

            return $"Authority: {i}";
        }
    }
}
