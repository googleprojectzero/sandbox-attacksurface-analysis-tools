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

using NtApiDotNet.Token;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace NtApiDotNet
{
    /// <summary>
    /// Class to represent a Security Atttribute.
    /// </summary>
    public sealed class ClaimSecurityAttribute
    {
        private static T[] ReadTyped<T>(IntPtr buffer, int count) where T : struct
        {
            int type_size = Marshal.SizeOf(typeof(T));
            List<T> res = new List<T>();
            while (count > 0)
            {
                res.Add((T)Marshal.PtrToStructure(buffer, typeof(T)));
                buffer += type_size;
                count--;
            }
            return res.ToArray();
        }

        private IEnumerable<object> ReadValues(IntPtr buffer, int count, ClaimSecurityValueType type)
        {
            if (buffer == IntPtr.Zero || count == 0)
            {
                return new object[0];
            }

            switch (type)
            {
                case ClaimSecurityValueType.Int64:
                    return ReadTyped<long>(buffer, count).Cast<object>();
                case ClaimSecurityValueType.UInt64:
                    return ReadTyped<ulong>(buffer, count).Cast<object>();
                case ClaimSecurityValueType.OctetString:
                    return ReadTyped<ClaimSecurityAttributeOctetStringValue>(buffer, count).Select(v => v.ToArray()).Cast<object>();
                case ClaimSecurityValueType.Sid:
                    return ReadTyped<ClaimSecurityAttributeOctetStringValue>(buffer, count).Select(v => v.ToSid()).Cast<object>();
                case ClaimSecurityValueType.Boolean:
                    return ReadTyped<long>(buffer, count).Select(v => v != 0).Cast<object>();
                case ClaimSecurityValueType.String:
                    return ReadTyped<UnicodeStringOut>(buffer, count).Select(n => n.ToString());
                case ClaimSecurityValueType.Fqbn:
                    return ReadTyped<ClaimSecurityAttributeFqbnValue>(buffer, count).Select(v => new ClaimSecurityAttributeFqbn(v)).Cast<object>();
                default:
                    return new object[0];
            }
        }

        /// <summary>
        /// The name of the attribute.
        /// </summary>
        public string Name { get; }
        /// <summary>
        /// The type of values.
        /// </summary>
        public ClaimSecurityValueType ValueType { get; }
        /// <summary>
        /// The attribute flags.
        /// </summary>
        public ClaimSecurityFlags Flags { get; }
        /// <summary>
        /// The list of values.
        /// </summary>
        public IEnumerable<object> Values { get; }
        /// <summary>
        /// The count of values.
        /// </summary>
        public int ValueCount { get; }

        /// <summary>
        /// Convert the attribute to a builder to modify it.
        /// </summary>
        /// <returns>The builder.</returns>
        public ClaimSecurityAttributeBuilder ToBuilder()
        {
            return ClaimSecurityAttributeBuilder.Create(this);
        }

        internal ClaimSecurityAttribute(IntPtr ptr)
        {
            ClaimSecurityAttributeV1 v1 = (ClaimSecurityAttributeV1)Marshal.PtrToStructure(ptr, typeof(ClaimSecurityAttributeV1));
            Name = v1.Name.ToString();
            ValueType = v1.ValueType;
            Flags = v1.Flags;
            var values = ReadValues(v1.Values, v1.ValueCount, v1.ValueType).ToArray();
            Values = values;
            ValueCount = values.Length;
        }

        internal ClaimSecurityAttribute(string name, ClaimSecurityValueType value_type, ClaimSecurityFlags flags, IEnumerable<object> values)
        {
            Name = name;
            ValueType = value_type;
            Flags = flags;
            var array = values.ToArray();
            Values = array;
            ValueCount = array.Length;
        }

        private static string ReadString(byte[] data, int offset)
        {
            StringBuilder builder = new StringBuilder();
            while (offset < data.Length)
            {
                char c = BitConverter.ToChar(data, offset);
                if (c == 0)
                {
                    break;
                }
                builder.Append(c);
                offset += 2;
            }
            return builder.ToString();
        }

        private static byte[] ReadOctets(byte[] data, int offset)
        {
            int length = BitConverter.ToInt32(data, offset);
            byte[] ret = new byte[length];
            Array.Copy(data, offset + 4, ret, 0, length);
            return ret;
        }

        private IEnumerable<object> ReadValues(byte[] data, BinaryReader reader, int count, ClaimSecurityValueType type)
        {
            List<object> ret = new List<object>();
            if (count == 0)
            {
                return new object[0];
            }

            IEnumerable<int> offsets = Enumerable.Range(0, count).Select(i => reader.ReadInt32());

            switch (type)
            {
                case ClaimSecurityValueType.Int64:
                    return offsets.Select(i => BitConverter.ToInt64(data, i)).Cast<object>();
                case ClaimSecurityValueType.UInt64:
                    return offsets.Select(i => BitConverter.ToUInt64(data, i)).Cast<object>();
                case ClaimSecurityValueType.OctetString:
                    return offsets.Select(i => ReadOctets(data, i)).Cast<object>();
                case ClaimSecurityValueType.Sid:
                    return offsets.Select(i => new Sid(ReadOctets(data, i))).Cast<object>();
                case ClaimSecurityValueType.Boolean:
                    return offsets.Select(i => BitConverter.ToUInt64(data, i) != 0).Cast<object>();
                case ClaimSecurityValueType.String:
                    return offsets.Select(i => ReadString(data, i)).Cast<object>();
                case ClaimSecurityValueType.Fqbn:
                    throw new ArgumentException("Unsupported claim type FQBN.");
                default:
                    return new object[0];
            }
        }

        internal ClaimSecurityAttribute(byte[] data)
        {
            BinaryReader reader = new BinaryReader(new MemoryStream(data));
            Name = ReadString(data, reader.ReadInt32());
            ValueType = (ClaimSecurityValueType)reader.ReadUInt16();
            // Reserved.
            reader.ReadInt16();
            Flags = (ClaimSecurityFlags)reader.ReadInt32();
            int count = reader.ReadInt32();
            var values = ReadValues(data, reader, count, ValueType).ToArray();
            Values = values;
            ValueCount = values.Length;
        }
    }

#pragma warning restore 1591
}
