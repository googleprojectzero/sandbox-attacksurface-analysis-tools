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
    /// <summary>
    /// Builder for a claim security attribute.
    /// </summary>
    public class ClaimSecurityAttributeBuilder
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

        private int GetValueSize()
        {
            switch (ValueType)
            {
                case ClaimSecurityValueType.Boolean:
                case ClaimSecurityValueType.Int64:
                case ClaimSecurityValueType.UInt64:
                    return Values.Count * sizeof(long);
                case ClaimSecurityValueType.String:
                    return Values.Count * Marshal.SizeOf(typeof(UnicodeStringOut));
                case ClaimSecurityValueType.OctetString:
                case ClaimSecurityValueType.Sid:
                    return Values.Count * Marshal.SizeOf(typeof(ClaimSecurityAttributeOctetStringValue));
                case ClaimSecurityValueType.Fqbn:
                    return Values.Count * Marshal.SizeOf(typeof(ClaimSecurityAttributeFqbnValue));
                default:
                    throw new ArgumentException($"Unknown attribute value type {ValueType}");
            }
        }

        private static UnicodeStringOut CreateString(string value, DisposableList list)
        {
            byte[] bytes = Encoding.Unicode.GetBytes(value + "\0");
            return new UnicodeStringOut
            {
                Length = (ushort)(bytes.Length - 2),
                MaximumLength = (ushort)bytes.Length,
                Buffer = list.AddResource(new SafeHGlobalBuffer(bytes)).DangerousGetHandle()
            };
        }

        private static ClaimSecurityAttributeOctetStringValue CreateOctetString(byte[] value, DisposableList list)
        {
            return new ClaimSecurityAttributeOctetStringValue
            {
                ValueLength = value.Length,
                pValue = list.AddResource(new SafeHGlobalBuffer(value)).DangerousGetHandle()
            };
        }

        private static ClaimSecurityAttributeFqbnValue CreateFqbnValue(ClaimSecurityAttributeFqbn value, DisposableList list)
        {
            return new ClaimSecurityAttributeFqbnValue
            {
                Version = NtObjectUtils.PackVersion(value.Version),
                Name = CreateString(value.Name, list)
            };
        }

        private SafeHGlobalBuffer MarshalValues(DisposableList list)
        {
            using (var buffer = new SafeHGlobalBuffer(GetValueSize()))
            {
                switch (ValueType)
                {
                    case ClaimSecurityValueType.Int64:
                        buffer.WriteArray(0, Values.Cast<long>().ToArray(), 0, Values.Count);
                        break;
                    case ClaimSecurityValueType.UInt64:
                        buffer.WriteArray(0, Values.Cast<ulong>().ToArray(), 0, Values.Count);
                        break;
                    case ClaimSecurityValueType.Boolean:
                        buffer.WriteArray(0, Values.Cast<bool>().Select(b => b ? 1L : 0L).ToArray(), 0, Values.Count);
                        break;
                    case ClaimSecurityValueType.String:
                        buffer.WriteArray(0, Values.Cast<string>().Select(s => CreateString(s, list)).ToArray(), 0, Values.Count);
                        break;
                    case ClaimSecurityValueType.OctetString:
                        buffer.WriteArray(0, Values.Cast<byte[]>().Select(ba => CreateOctetString(ba, list)).ToArray(), 0, Values.Count);
                        break;
                    case ClaimSecurityValueType.Sid:
                        buffer.WriteArray(0, Values.Cast<Sid>().Select(s => CreateOctetString(s.ToArray(), list)).ToArray(), 0, Values.Count);
                        break;
                    case ClaimSecurityValueType.Fqbn:
                        buffer.WriteArray(0, Values.Cast<ClaimSecurityAttributeFqbn>().Select(v => CreateFqbnValue(v, list)).ToArray(), 0, Values.Count);
                        break;
                }

                return buffer.Detach();
            }
        }

        internal ClaimSecurityAttributeV1 MarshalAttribute(DisposableList list)
        {
            return new ClaimSecurityAttributeV1
            {
                ValueType = ValueType,
                Values = list.AddResource(MarshalValues(list)).DangerousGetHandle(),
                ValueCount = Values.Count,
                Name = CreateString(Name, list),
                Flags = Flags
            };
        }
    }
}
