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
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace NtApiDotNet.Token
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct ClaimSecurityAttributeV1In
    {
        public UnicodeStringIn Name;
        public ClaimSecurityValueType ValueType;
        public ushort Reserved;
        public ClaimSecurityFlags Flags;
        public int ValueCount;
        public IntPtr Values;
        //union {
        //PLONG64 pInt64;
        //PDWORD64 pUint64;
        //UNICODE_STRING* ppString;
        //PCLAIM_SECURITY_ATTRIBUTE_FQBN_VALUE pFqbn;
        //PCLAIM_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE pOctetString;
    }

    /// <summary>
    /// Builder for a claim security attribute.
    /// </summary>
    internal class ClaimSecurityAttributeBuilder
    {
        private class WrapperList<T> : List<T>, IList<object>
        {
            public WrapperList()
            {
            }

            public WrapperList(IEnumerable<T> collection) 
                : base(collection)
            {
            }

            object IList<object>.this[int index] { get => this[index]; set => this[index] = (T)value; }

            bool ICollection<object>.IsReadOnly => ((ICollection<T>)this).IsReadOnly;

            void ICollection<object>.Add(object item)
            {
                Add((T)item);
            }

            bool ICollection<object>.Contains(object item)
            {
                return Contains((T)item);
            }

            void ICollection<object>.CopyTo(object[] array, int arrayIndex)
            {
                CopyTo(array.Cast<T>().ToArray(), arrayIndex);
            }

            IEnumerator<object> IEnumerable<object>.GetEnumerator()
            {
                return this.Cast<object>().GetEnumerator();
            }

            int IList<object>.IndexOf(object item)
            {
                return IndexOf((T)item);
            }

            void IList<object>.Insert(int index, object item)
            {
                Insert(index, (T)item);
            }

            bool ICollection<object>.Remove(object item)
            {
                return Remove((T)item);
            }

            void IList<object>.RemoveAt(int index)
            {
                RemoveAt(index);
            }
        }

        /// <summary>
        /// Name of the security attribute.
        /// </summary>
        public string Name { get; set; }
        /// <summary>
        /// Attribute flags.
        /// </summary>
        public ClaimSecurityFlags Flags { get; set; }
        /// <summary>
        /// The value type.
        /// </summary>
        public ClaimSecurityValueType ValueType { get; }
        /// <summary>
        /// The current list of values.
        /// </summary>
        public IList<object> Values { get; }

        private ClaimSecurityAttributeBuilder(string name, ClaimSecurityFlags flags, ClaimSecurityValueType value_type, IList<object> values)
        {
            Name = name;
            Flags = flags;
            ValueType = value_type;
            Values = values;
        }

        private static ClaimSecurityAttributeBuilder CreateInternal<T>(string name, ClaimSecurityFlags flags,
            ClaimSecurityValueType value_type, IEnumerable<T> values)
        {
            return new ClaimSecurityAttributeBuilder(name, flags, value_type, new WrapperList<T>(values));
        }

        /// <summary>
        /// Create a claim security attribute builder.
        /// </summary>
        /// <param name="name">The name of the security attribute.</param>
        /// <param name="flags">The attribute flags.</param>
        /// <param name="values">The value for the attribute.</param>
        /// <returns>The builder instance.</returns>
        public static ClaimSecurityAttributeBuilder Create(string name, ClaimSecurityFlags flags, params long[] values)
        {
            return CreateInternal(name, flags, ClaimSecurityValueType.Int64, values);
        }

        /// <summary>
        /// Create a claim security attribute builder.
        /// </summary>
        /// <param name="name">The name of the security attribute.</param>
        /// <param name="flags">The attribute flags.</param>
        /// <param name="values">The value for the attribute.</param>
        /// <returns>The builder instance.</returns>
        public static ClaimSecurityAttributeBuilder Create(string name, ClaimSecurityFlags flags, params ulong[] values)
        {
            return CreateInternal(name, flags, ClaimSecurityValueType.UInt64, values);
        }

        /// <summary>
        /// Create a claim security attribute builder.
        /// </summary>
        /// <param name="name">The name of the security attribute.</param>
        /// <param name="flags">The attribute flags.</param>
        /// <param name="values">The value for the attribute.</param>
        /// <returns>The builder instance.</returns>
        public static ClaimSecurityAttributeBuilder Create(string name, ClaimSecurityFlags flags, params byte[][] values)
        {
            return CreateInternal(name, flags, ClaimSecurityValueType.OctetString, values);
        }

        /// <summary>
        /// Create a claim security attribute builder.
        /// </summary>
        /// <param name="name">The name of the security attribute.</param>
        /// <param name="flags">The attribute flags.</param>
        /// <param name="values">The value for the attribute.</param>
        /// <returns>The builder instance.</returns>
        public static ClaimSecurityAttributeBuilder Create(string name, ClaimSecurityFlags flags, params Sid[] values)
        {
            return CreateInternal(name, flags, ClaimSecurityValueType.Sid, values);
        }

        /// <summary>
        /// Create a claim security attribute builder.
        /// </summary>
        /// <param name="name">The name of the security attribute.</param>
        /// <param name="flags">The attribute flags.</param>
        /// <param name="values">The value for the attribute.</param>
        /// <returns>The builder instance.</returns>
        public static ClaimSecurityAttributeBuilder Create(string name, ClaimSecurityFlags flags, params bool[] values)
        {
            return CreateInternal(name, flags, ClaimSecurityValueType.Boolean, values);
        }

        /// <summary>
        /// Create a claim security attribute builder.
        /// </summary>
        /// <param name="name">The name of the security attribute.</param>
        /// <param name="flags">The attribute flags.</param>
        /// <param name="values">The value for the attribute.</param>
        /// <returns>The builder instance.</returns>
        public static ClaimSecurityAttributeBuilder Create(string name, ClaimSecurityFlags flags, params string[] values)
        {
            return CreateInternal(name, flags, ClaimSecurityValueType.String, values);
        }

        /// <summary>
        /// Create a claim security attribute builder.
        /// </summary>
        /// <param name="name">The name of the security attribute.</param>
        /// <param name="flags">The attribute flags.</param>
        /// <param name="values">The value for the attribute.</param>
        /// <returns>The builder instance.</returns>
        public static ClaimSecurityAttributeBuilder Create(string name, ClaimSecurityFlags flags, params ClaimSecurityAttributeFqbn[] values)
        {
            return CreateInternal(name, flags, ClaimSecurityValueType.Fqbn, values.Select(o => o.Clone()));
        }

        /// <summary>
        /// Create a claim security attribute builder.
        /// </summary>
        /// <param name="attribute">An existing attribute to clone.</param>
        /// <returns>The builder instance.</returns>
        public static ClaimSecurityAttributeBuilder Create(ClaimSecurityAttribute attribute)
        {
            switch (attribute.ValueType)
            {
                case ClaimSecurityValueType.Boolean:
                    return Create(attribute.Name, attribute.Flags, attribute.Values.Cast<bool>().ToArray());
                case ClaimSecurityValueType.Fqbn:
                    return Create(attribute.Name, attribute.Flags, attribute.Values.Cast<ClaimSecurityAttributeFqbn>().ToArray());
                case ClaimSecurityValueType.Int64:
                    return Create(attribute.Name, attribute.Flags, attribute.Values.Cast<long>().ToArray());
                case ClaimSecurityValueType.OctetString:
                    return Create(attribute.Name, attribute.Flags, attribute.Values.Cast<byte[]>().ToArray());
                case ClaimSecurityValueType.Sid:
                    return Create(attribute.Name, attribute.Flags, attribute.Values.Cast<Sid>().ToArray());
                case ClaimSecurityValueType.String:
                    return Create(attribute.Name, attribute.Flags, attribute.Values.Cast<string>().ToArray());
                case ClaimSecurityValueType.UInt64:
                    return Create(attribute.Name, attribute.Flags, attribute.Values.Cast<ulong>().ToArray());
                default:
                    throw new ArgumentException($"Unknown attribute value type {attribute.ValueType}");
            }
        }

        private List<byte[]> MarshalValues()
        {
            List<byte[]> ret = new List<byte[]>();
            foreach (var value in Values)
            {
                if (value is bool b)
                {
                    ret.Add(BitConverter.GetBytes(b ? 1L : 0L));
                }
                else if (value is long l)
                {
                    ret.Add(BitConverter.GetBytes(l));
                }
                else if (value is ulong u)
                {
                    ret.Add(BitConverter.GetBytes(u));
                }
                else if (value is byte[] ba)
                {
                    ret.Add(ba);
                }
                else if (value is Sid sid)
                {
                    ret.Add(sid.ToArray());
                }
                else if (value is string s)
                {
                    ret.Add(Encoding.Unicode.GetBytes(s + "\0"));
                }
                else if (value is ClaimSecurityAttributeFqbn c)
                {
                    ret.Add(Encoding.Unicode.GetBytes(c.Name + "\0"));
                }
                else
                {
                    throw new ArgumentException("Unknown value type");
                }
            }
            return ret;
        }

        private int GetValueSize(List<byte[]> values)
        {
            int value_size = values.Sum(v => v.Length);
            switch (ValueType)
            {
                case ClaimSecurityValueType.Boolean:
                case ClaimSecurityValueType.Int64:
                case ClaimSecurityValueType.UInt64:
                    return value_size;
                case ClaimSecurityValueType.String:
                    return Values.Count * Marshal.SizeOf(typeof(UnicodeStringOut)) + value_size;
                case ClaimSecurityValueType.OctetString:
                case ClaimSecurityValueType.Sid:
                    return Values.Count * Marshal.SizeOf(typeof(ClaimSecurityAttributeOctetStringValue)) + value_size;
                case ClaimSecurityValueType.Fqbn:
                    return Values.Count * Marshal.SizeOf(typeof(ClaimSecurityAttributeFqbnValue)) + value_size;
                default:
                    throw new ArgumentException($"Unknown attribute value type {ValueType}");
            }
        }

        internal SafeHGlobalBuffer ToSafeBuffer()
        {
            var value_data = MarshalValues();
            int value_size = GetValueSize(value_data);

            using (var buffer = new SafeHGlobalBuffer(value_size))
            {
                switch (ValueType)
                {
                    case ClaimSecurityValueType.Int64:
                    case ClaimSecurityValueType.UInt64:
                    case ClaimSecurityValueType.Boolean:
                        buffer.WriteArray(0, Values.Cast<bool>().Select(b => b ? 1L : 0L).ToArray(), 0, Values.Count);
                        break;
                }
                return buffer.Detach();
            }
        }
    }
}
