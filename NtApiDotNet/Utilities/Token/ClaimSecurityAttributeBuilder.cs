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
using System.Text;

namespace NtApiDotNet.Token
{
    /// <summary>
    /// Builder for a claim security attribute.
    /// </summary>
    public class ClaimSecurityAttributeBuilder
    {
        #region Private Members
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

            void ICollection<object>.Add(object item) => Add((T)item);

            bool ICollection<object>.Contains(object item) => Contains((T)item);

            void ICollection<object>.CopyTo(object[] array, int arrayIndex)
            {
                for (int i = 0; i < Count; ++i)
                {
                    array[arrayIndex + i] = this[i];
                }
            }

            IEnumerator<object> IEnumerable<object>.GetEnumerator() => this.Cast<object>().GetEnumerator();

            int IList<object>.IndexOf(object item) => IndexOf((T)item);

            void IList<object>.Insert(int index, object item) => Insert(index, (T)item);

            bool ICollection<object>.Remove(object item) => Remove((T)item);

            void IList<object>.RemoveAt(int index) => RemoveAt(index);
        }

        private static ClaimSecurityAttributeBuilder CreateInternal<T>(string name, ClaimSecurityFlags flags,
            ClaimSecurityValueType value_type, IEnumerable<T> values)
        {
            return new ClaimSecurityAttributeBuilder(name, flags, value_type, new WrapperList<T>(values));
        }

        private int GetValueSize(bool native)
        {
            switch (ValueType)
            {
                case ClaimSecurityValueType.Boolean:
                case ClaimSecurityValueType.Int64:
                case ClaimSecurityValueType.UInt64:
                    return Values.Count * sizeof(long);
                case ClaimSecurityValueType.String:
                    if (native)
                    {
                        return Values.Count * Marshal.SizeOf(typeof(UnicodeStringOut));
                    }
                    else
                    {
                        return Values.Count * IntPtr.Size;
                    }
                case ClaimSecurityValueType.OctetString:
                case ClaimSecurityValueType.Sid:
                    return Values.Count * Marshal.SizeOf(typeof(ClaimSecurityAttributeOctetStringValue));
                case ClaimSecurityValueType.Fqbn:
                    if (native)
                    {
                        return Values.Count * Marshal.SizeOf(typeof(SecurityAttributeFqbnValue));
                    }
                    else
                    {
                        return Values.Count * Marshal.SizeOf(typeof(ClaimSecurityAttributeFqbnValue));
                    }
                default:
                    throw new ArgumentException($"Unknown attribute value type {ValueType}");
            }
        }

        private static UnicodeStringOut CreateUnicodeString(string value, DisposableList list)
        {
            byte[] bytes = Encoding.Unicode.GetBytes(value + "\0");
            return new UnicodeStringOut
            {
                Length = (ushort)(bytes.Length - 2),
                MaximumLength = (ushort)bytes.Length,
                Buffer = list.AddResource(new SafeHGlobalBuffer(bytes)).DangerousGetHandle()
            };
        }

        private static IntPtr CreateString(string value, DisposableList list)
        {
            byte[] bytes = Encoding.Unicode.GetBytes(value + "\0");
            return list.AddResource(new SafeHGlobalBuffer(bytes)).DangerousGetHandle();
        }

        private static ClaimSecurityAttributeOctetStringValue CreateOctetString(byte[] value, DisposableList list)
        {
            return new ClaimSecurityAttributeOctetStringValue
            {
                ValueLength = value.Length,
                pValue = list.AddResource(new SafeHGlobalBuffer(value)).DangerousGetHandle()
            };
        }

        private static SecurityAttributeFqbnValue CreateNativeFqbnValue(ClaimSecurityAttributeFqbn value, DisposableList list)
        {
            return new SecurityAttributeFqbnValue
            {
                Version = NtObjectUtils.PackVersion(value.Version),
                Name = CreateUnicodeString(value.Name, list)
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

        private SafeHGlobalBuffer MarshalValues(DisposableList list, bool native)
        {
            using (var buffer = new SafeHGlobalBuffer(GetValueSize(native)))
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
                        if (native)
                        {
                            buffer.WriteArray(0, Values.Cast<string>().Select(s => CreateUnicodeString(s, list)).ToArray(), 0, Values.Count);
                        }
                        else
                        {
                            buffer.WriteArray(0, Values.Cast<string>().Select(s => CreateString(s, list)).ToArray(), 0, Values.Count);
                        }
                        break;
                    case ClaimSecurityValueType.OctetString:
                        buffer.WriteArray(0, Values.Cast<byte[]>().Select(ba => CreateOctetString(ba, list)).ToArray(), 0, Values.Count);
                        break;
                    case ClaimSecurityValueType.Sid:
                        buffer.WriteArray(0, Values.Cast<Sid>().Select(s => CreateOctetString(s.ToArray(), list)).ToArray(), 0, Values.Count);
                        break;
                    case ClaimSecurityValueType.Fqbn:
                        if (native)
                        {
                            buffer.WriteArray(0, Values.Cast<ClaimSecurityAttributeFqbn>().Select(v => CreateNativeFqbnValue(v, list)).ToArray(), 0, Values.Count);
                        }
                        else
                        {
                            buffer.WriteArray(0, Values.Cast<ClaimSecurityAttributeFqbn>().Select(v => CreateFqbnValue(v, list)).ToArray(), 0, Values.Count);
                        }
                        break;
                }

                return buffer.Detach();
            }
        }

        private static void Align(BinaryWriter writer)
        {
            int remaining = (int)writer.BaseStream.Length % 4;
            if (remaining != 0)
            {
                writer.Write(new byte[4 - remaining]);
            }
        }

        private static int WriteString(BinaryWriter writer, string str)
        {
            int offset = (int)writer.BaseStream.Position;
            writer.Write((str + "\0").ToCharArray());
            Align(writer);
            return offset;
        }

        private static int WriteOctet(BinaryWriter writer, byte[] data)
        {
            int offset = (int)writer.BaseStream.Position;
            writer.Write(data.Length);
            writer.Write(data);
            Align(writer);
            return offset;
        }

        private static int WriteValue<T>(BinaryWriter writer, Action<T> func, T value)
        {
            int offset = (int)writer.BaseStream.Position;
            func(value);
            Align(writer);
            return offset;
        }

        private Tuple<int[], byte[]> MarshalValues()
        {
            MemoryStream stm = new MemoryStream();
            BinaryWriter writer = new BinaryWriter(stm, Encoding.Unicode);
            IEnumerable<int> offsets;
            WriteString(writer, Name);
            switch (ValueType)
            {
                case ClaimSecurityValueType.Int64:
                    offsets = Values.Cast<long>().Select(v => WriteValue(writer, writer.Write, v));
                    break;
                case ClaimSecurityValueType.UInt64:
                    offsets = Values.Cast<ulong>().Select(v => WriteValue(writer, writer.Write, v));
                    break;
                case ClaimSecurityValueType.Boolean:
                    offsets = Values.Cast<bool>().Select(v => WriteValue(writer, writer.Write, v ? 1L : 0L));
                    break;
                case ClaimSecurityValueType.String:
                    offsets = Values.Cast<string>().Select(v => WriteString(writer, v));
                    break;
                case ClaimSecurityValueType.OctetString:
                    offsets = Values.Cast<byte[]>().Select(v => WriteOctet(writer, v));
                    break;
                case ClaimSecurityValueType.Sid:
                    offsets = Values.Cast<Sid>().Select(v => WriteOctet(writer, v.ToArray()));
                    break;
                default:
                    throw new ArgumentException($"Unsupported claim type {ValueType}.");
            }
            return Tuple.Create(offsets.ToArray(), stm.ToArray());
        }

        #endregion

        #region Public Properties
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
        #endregion

        #region Public Methods

        /// <summary>
        /// Convert build to a claim attribute.
        /// </summary>
        /// <returns></returns>
        public ClaimSecurityAttribute ToAttribute()
        {
            return new ClaimSecurityAttribute(Name, ValueType, Flags, Values);
        }

        #endregion

        #region Static Methods
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
        #endregion

        #region Constructors
        private ClaimSecurityAttributeBuilder(string name, ClaimSecurityFlags flags, ClaimSecurityValueType value_type, IList<object> values)
        {
            Name = name;
            Flags = flags;
            ValueType = value_type;
            Values = values;
        }
        #endregion

        #region Internal Members
        internal SecurityAttributeV1 MarshalNativeAttribute(DisposableList list)
        {
            return new SecurityAttributeV1
            {
                ValueType = ValueType,
                Values = list.AddResource(MarshalValues(list, true)).DangerousGetHandle(),
                ValueCount = Values.Count,
                Name = CreateUnicodeString(Name, list),
                Flags = Flags
            };
        }

        internal ClaimSecurityAttributeV1 MarshalAttribute(DisposableList list)
        {
            return new ClaimSecurityAttributeV1
            {
                ValueType = ValueType,
                Values = list.AddResource(MarshalValues(list, true)).DangerousGetHandle(),
                ValueCount = Values.Count,
                Name = CreateString(Name, list),
                Flags = Flags
            };
        }

        internal byte[] MarshalAttribute()
        {
            MemoryStream stm = new MemoryStream();
            BinaryWriter writer = new BinaryWriter(stm);
            var values = MarshalValues();

            int header_size = 16 + Values.Count * 4;
            // Name offset.
            writer.Write(header_size);
            writer.Write((ushort)ValueType);
            writer.Write((ushort)0);
            writer.Write((int)Flags);
            writer.Write(Values.Count);
            foreach (int offset in values.Item1)
            {
                writer.Write(offset + header_size);
            }
            writer.Write(values.Item2);
            return stm.ToArray();
        }

        internal static SafeBuffer ToSafeBuffer(DisposableList list, ClaimSecurityAttributeBuilder[] attributes, bool native)
        {
            SafeBuffer attrs;
            if (native)
            {
                attrs = list.AddResource(attributes.Select(a => a.MarshalNativeAttribute(list)).ToArray().ToBuffer());
            }
            else
            {
                attrs = list.AddResource(attributes.Select(a => a.MarshalAttribute(list)).ToArray().ToBuffer());
            }

            return new ClaimSecurityAttributesInformation
            {
                Version = 1,
                AttributeCount = attributes.Length,
                pAttributeV1 = attrs.DangerousGetHandle()
            }.ToBuffer();
        }

        #endregion
    }
}
