//  Copyright 2021 Google LLC. All Rights Reserved.
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
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Text;

namespace NtApiDotNet.Utilities.ASN1.Builder
{
    /// <summary>
    /// Class to do basic ASN1 DER generation.
    /// </summary>
    public class DERBuilder
    {
        #region Private Members
        private readonly Stream _stm;
        private readonly BinaryWriter _writer;
        #endregion

        #region Constructors
        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="stm">The stream to write the DER data to.</param>
        public DERBuilder(Stream stm)
        {
            _stm = stm;
            _writer = new BinaryWriter(stm);
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        public DERBuilder() : this(new MemoryStream())
        {
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Write an object ID.
        /// </summary>
        /// <param name="oid">The object ID to write.</param>
        public void WriteObjectId(string oid)
        {
            var values = oid.Split('.').Select(i => int.Parse(i)).ToArray();
            if (values.Length < 2)
                throw new ArgumentException("Invalid OID string, needs at least two components.", nameof(oid));
            _writer.WriteUniversalValue(false, UniversalTag.OBJECT_IDENTIFIER, w =>
            {
                w.WriteByte(values[0] * 40 + values[1]);
                foreach (var value in values.Skip(2))
                {
                    w.WriteEncodedInt(value);
                }
            });
        }

        /// <summary>
        /// Write raw bytes to the stream.
        /// </summary>
        /// <param name="ba">The bytes to write.</param>
        public void WriteRawBytes(byte[] ba)
        {
            _writer.Write(ba);
        }

        /// <summary>
        /// Write an octet-string to the stream.
        /// </summary>
        /// <param name="octet_string">The octet string.</param>
        public void WriteOctetString(byte[] octet_string)
        {
            _writer.WriteUniversalValue(false, UniversalTag.OCTET_STRING, octet_string);
        }

        /// <summary>
        /// Write a NULL value.
        /// </summary>
        public void WriteNull()
        {
            _writer.WriteUniversalValue(false, UniversalTag.NULL, new byte[0]);
        }

        /// <summary>
        /// Write a 32-bit integer.
        /// </summary>
        /// <param name="value">The integer value.</param>
        public void WriteInt32(int value)
        {
            WriteInteger(new BigInteger(value));
        }

        /// <summary>
        /// Write a 64-bit integer.
        /// </summary>
        /// <param name="value">The integer value.</param>
        public void WriteInt64(long value)
        {
            WriteInteger(new BigInteger(value));
        }

        /// <summary>
        /// Write an arbitrary integer.
        /// </summary>
        /// <param name="value">The integer value.</param>
        public void WriteInteger(BigInteger value)
        {
            _writer.WriteUniversalValue(false, UniversalTag.INTEGER, value.ToByteArray().Reverse().ToArray()); 
        }

        /// <summary>
        /// Write a boolean.
        /// </summary>
        /// <param name="value">The boolean value to write.</param>
        public void WriteBoolean(bool value)
        {
            _writer.WriteUniversalValue(false, UniversalTag.BOOLEAN, new byte[] { (byte)(value ? 0xFF : 0) });
        }

        /// <summary>
        /// Write a DER object.
        /// </summary>
        /// <param name="obj">The object to write.</param>
        public void WriteObject(IDERObject obj)
        {
            obj.Write(this);
        }

        /// <summary>
        /// Write a sequence based on the contents of another DER builder.
        /// </summary>
        /// <param name="builder">The builder for the contents.</param>
        public void WriteSequence(DERBuilder builder)
        {
            _writer.WriteUniversalValue(true, UniversalTag.SEQUENCE, builder.ToArray());
        }

        /// <summary>
        /// Write a sequence based on the contents of another DER builder.
        /// </summary>
        /// <param name="build">The build function for the contents.</param>
        public void WriteSequence(Action<DERBuilder> build)
        {
            using (var seq = CreateSequence())
            {
                build(seq);
            }
        }

        /// <summary>
        /// Write a sequence based on the a set of values.
        /// </summary>
        /// <param name="values">Write a sequence of fixed values.</param>
        /// <param name="build">The build function for the contents.</param>
        public void WriteSequence<T>(IEnumerable<T> values, Action<DERBuilder, T> build)
        {
            using (var seq = CreateSequence())
            {
                foreach (var value in values)
                {
                    build(seq, value);
                }
            }
        }

        /// <summary>
        /// Write a sequence based on the a set of values.
        /// </summary>
        /// <param name="values">Write a sequence of DER objects.</param>
        public void WriteSequence(IEnumerable<IDERObject> values)
        {
            WriteSequence(values, (b, v) => v.Write(b));
        }

        /// <summary>
        /// Write a sequence of general strings.
        /// </summary>
        /// <param name="strs">The strings to write.</param>
        public void WriteGeneralStringSequence(IEnumerable<string> strs)
        {
            WriteSequence(strs, (b, s) => b.WriteGeneralString(s));
        }

        /// <summary>
        /// Create a sequence builder.
        /// </summary>
        /// <returns>The created builder.</returns>
        /// <remarks>You should call Close or dispose on the created builder to write the tag.</remarks>
        public DERBuilderSubStructure CreateSequence()
        {
            return new DERBuilderSubStructure(WriteSequence);
        }

        /// <summary>
        /// Write an application specific tag with contents from the builder.
        /// </summary>
        /// <param name="application">The ID of the application specific tag.</param>
        /// <param name="builder">The builder for the contents.</param>
        public void WriteApplication(int application, DERBuilder builder)
        {
            _writer.WriteTaggedValue(DERTagType.Application, true, application, builder.ToArray());
        }

        /// <summary>
        /// Write an application specific tag with contents from the builder.
        /// </summary>
        /// <param name="application">The ID of the application specific tag.</param>
        /// <param name="build">The build function for the contents.</param>
        public void WriteApplication(int application, Action<DERBuilder> build)
        {
            using (var app = CreateApplication(application))
            {
                build(app);
            }
        }

        /// <summary>
        /// Write an application specific tag with contents from an object.
        /// </summary>
        /// <param name="application">The ID of the application specific tag.</param>
        /// <param name="obj">The object to write.</param>
        public void WriteApplication(int application, IDERObject obj)
        {
            WriteApplication(application, obj.Write);
        }

        /// <summary>
        /// Create an application specific builder.
        /// </summary>
        /// <param name="application">The ID of the application specific tag.</param>
        /// <returns>The created builder.</returns>
        /// <remarks>You should call Close or dispose on the created builder to write the tag.</remarks>
        public DERBuilderSubStructure CreateApplication(int application)
        {
            return new DERBuilderSubStructure(b => WriteApplication(application, b));
        }

        /// <summary>
        /// Write an context specific tag with contents from the builder.
        /// </summary>
        /// <param name="context">The ID of the context specific tag.</param>
        /// <param name="builder">The DER builder to write.</param>
        public void WriteContextSpecific(int context, DERBuilder builder)
        {
            _writer.WriteTaggedValue(DERTagType.ContextSpecific, true, context, builder.ToArray());
        }

        /// <summary>
        /// Write an context specific tag with contents from the builder.
        /// </summary>
        /// <param name="context">The ID of the context specific tag.</param>
        /// <param name="build">The build function for the contents.</param>
        public void WriteContextSpecific(int context, Action<DERBuilder> build)
        {
            using (var seq = CreateContextSpecific(context))
            {
                build(seq);
            }
        }

        /// <summary>
        /// Write an context specific tag with an object.
        /// </summary>
        /// <param name="context">The ID of the context specific tag.</param>
        /// <param name="obj">The object to write.</param>
        public void WriteContextSpecific(int context, IDERObject obj)
        {
            if (obj == null)
                return;
            WriteContextSpecific(context, b => obj.Write(b));
        }

        /// <summary>
        /// Write an context specific tag with an int32.
        /// </summary>
        /// <param name="context">The ID of the context specific tag.</param>
        /// <param name="value">The value to write.</param>
        public void WriteContextSpecific(int context, int? value)
        {
            if (!value.HasValue)
                return;
            WriteContextSpecific(context, b => b.WriteInt32(value.Value));
        }

        /// <summary>
        /// Write an context specific tag with an sequence of objects.
        /// </summary>
        /// <param name="context">The ID of the context specific tag.</param>
        /// <param name="objs">The objects to write.</param>
        public void WriteContextSpecific(int context, IEnumerable<IDERObject> objs)
        {
            if (objs == null)
                return;
            WriteContextSpecific(context, b => b.WriteSequence(objs));
        }

        /// <summary>
        /// Write an context specific tag with a general string.
        /// </summary>
        /// <param name="context">The ID of the context specific tag.</param>
        /// <param name="value">The value to write.</param>
        public void WriteContextSpecific(int context, string value)
        {
            if (value == null)
                return;
            WriteContextSpecific(context, b => b.WriteGeneralString(value));
        }

        /// <summary>
        /// Write an context specific tag with a sequence of general strings.
        /// </summary>
        /// <param name="context">The ID of the context specific tag.</param>
        /// <param name="value">The value to write.</param>
        public void WriteContextSpecific(int context, IEnumerable<string> value)
        {
            if (value == null)
                return;
            WriteContextSpecific(context, b => b.WriteGeneralStringSequence(value));
        }

        /// <summary>
        /// Write an context specific tag with an OCTET STRING.
        /// </summary>
        /// <param name="context">The ID of the context specific tag.</param>
        /// <param name="value">The value to write.</param>
        public void WriteContextSpecific(int context, byte[] value)
        {
            if (value == null)
                return;
            WriteContextSpecific(context, b => b.WriteOctetString(value));
        }


        /// <summary>
        /// Write an context specific tag with an BITSTRING
        /// </summary>
        /// <param name="context">The ID of the context specific tag.</param>
        /// <param name="value">The value to write.</param>
        public void WriteContextSpecific(int context, BitArray value)
        {
            if (value == null)
                return;
            WriteContextSpecific(context, b => b.WriteBitString(value));
        }

        /// <summary>
        /// Create a context specific builder.
        /// </summary>
        /// <param name="context">The ID of the context specific tag.</param>
        /// <returns>The created builder.</returns>
        /// <remarks>You should call Close or dispose on the created builder to write the tag.</remarks>
        public DERBuilderSubStructure CreateContextSpecific(int context)
        {
            return new DERBuilderSubStructure(b => WriteContextSpecific(context, b));
        }

        /// <summary>
        /// Write a general encoded string.
        /// </summary>
        /// <param name="str">The string</param>
        /// <param name="encoding">The encoding to covert to.</param>
        public void WriteGeneralString(string str, Encoding encoding)
        {
            _writer.WriteUniversalValue(false, UniversalTag.GeneralString, encoding.GetBytes(str));
        }

        /// <summary>
        /// Write a general encoded string using ASCII encoding.
        /// </summary>
        /// <param name="str">The string</param>
        public void WriteGeneralString(string str)
        {
            WriteGeneralString(str, Encoding.ASCII);
        }

        /// <summary>
        /// Write a UTF8 string.
        /// </summary>
        /// <param name="str">The UTF8 string</param>
        public void WriteUTF8String(string str)
        {
            _writer.WriteUniversalValue(false, UniversalTag.UTF8String, Encoding.UTF8.GetBytes(str));
        }

        /// <summary>
        /// Write an IA5 string.
        /// </summary>
        /// <param name="str">The IA5 string</param>
        public void WriteIA5String(string str)
        {
            _writer.WriteUniversalValue(false, UniversalTag.IA5String, Encoding.ASCII.GetBytes(str));
        }

        /// <summary>
        /// Write a generalized time.
        /// </summary>
        /// <param name="time">The time to write.</param>
        public void WriteGeneralizedTime(string time)
        {
            _writer.WriteUniversalValue(false, UniversalTag.GeneralizedTime, Encoding.ASCII.GetBytes(time));
        }

        /// <summary>
        /// Write a generalized time.
        /// </summary>
        /// <param name="time">The time to write.</param>
        public void WriteGeneralizedTime(DateTime time)
        {
            WriteGeneralizedTime(DERUtils.ConvertGeneralizedTime(time));
        }

        /// <summary>
        /// Write a bit array.
        /// </summary>
        /// <param name="bits">The bits to write.</param>
        public void WriteBitString(int bits)
        {
            WriteBitString(new BitArray(BitConverter.GetBytes(bits)));
        }

        /// <summary>
        /// Write a bit array.
        /// </summary>
        /// <param name="bits">The bits to write.</param>
        public void WriteBitString(BitArray bits)
        {
            int byte_count = (bits.Length + 7) / 8;

            byte[] data = new byte[byte_count + 1];

            for (int i = 0; i < bits.Length; ++i)
            {
                if (!bits[i])
                    continue;
                int array_pos = (i / 8) + 1;
                int bit_pos = 7 - (i & 7);
                data[array_pos] |= (byte)(1 << bit_pos);
            }

            int remaining = bits.Length % 8;
            if (remaining > 0)
            {
                data[0] = (byte)(7 - remaining);
            }
            _writer.WriteUniversalValue(false, UniversalTag.BIT_STRING, data);
        }

        /// <summary>
        /// Write a 32-bit value as a bit string.
        /// </summary>
        /// <param name="convertible">The value. Must be convertable to UInt32.</param>
        public void WriteBitString(IConvertible convertible)
        {
            uint value = convertible.ToUInt32(null);
            BitArray bits = new BitArray(32, false);
            for (int i = 0; i < 32; ++i)
            {
                uint mask = (1U << i);
                bits[i] = ((value & mask) != 0);
            }
            WriteBitString(bits);
        }

        /// <summary>
        /// Convert builder to a byte array.
        /// </summary>
        /// <returns>The DER encoded data.</returns>
        public byte[] ToArray()
        {
            if (_stm is MemoryStream stm)
                return stm.ToArray();
            throw new InvalidOperationException("Inner stream must be a MemoryStream to convert to a byte array.");
        }
        #endregion
    }
}
