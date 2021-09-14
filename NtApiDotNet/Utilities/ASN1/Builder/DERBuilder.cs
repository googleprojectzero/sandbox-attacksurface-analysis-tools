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
        private readonly Stream _stm;
        private readonly BinaryWriter _writer;

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
        /// Write a sequence based on the contents of another DER builder.
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
        /// Create a sequence builder.
        /// </summary>
        /// <returns>The created builder.</returns>
        /// <remarks>You should call Close or dispose on the created builder to write the tag.</remarks>
        public DERBuilderSubStructure CreateSequence()
        {
            return new DERBuilderSubStructure(this, WriteSequence);
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
            using (var seq = CreateApplication(application))
            {
                build(seq);
            }
        }

        /// <summary>
        /// Create an application specific builder.
        /// </summary>
        /// <param name="application">The ID of the application specific tag.</param>
        /// <returns>The created builder.</returns>
        /// <remarks>You should call Close or dispose on the created builder to write the tag.</remarks>
        public DERBuilderSubStructure CreateApplication(int application)
        {
            return new DERBuilderSubStructure(this, b => WriteApplication(application, b));
        }

        /// <summary>
        /// Write a context specific tag with specified contents.
        /// </summary>
        /// <param name="context">The ID of the context specific tag.</param>
        /// <param name="data">The contents of the context specific value.</param>
        public void WriteContextSpecific(int context, byte[] data)
        {
            _writer.WriteTaggedValue(DERTagType.ContextSpecific, true, context, data);
        }

        /// <summary>
        /// Write a context specific tag with contents from the builder.
        /// </summary>
        /// <param name="context">The ID of the context specific tag.</param>
        /// <param name="builder">The builder for the contents.</param>
        public void WriteContextSpecific(int context, DERBuilder builder)
        {
            WriteContextSpecific(context, builder.ToArray());
        }

        /// <summary>
        /// Write an application specific tag with contents from the builder.
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
        /// Create a context specific builder.
        /// </summary>
        /// <param name="context">The ID of the context specific tag.</param>
        /// <returns>The created builder.</returns>
        /// <remarks>You should call Close or dispose on the created builder to write the tag.</remarks>
        public DERBuilderSubStructure CreateContextSpecific(int context)
        {
            return new DERBuilderSubStructure(this, b => WriteContextSpecific(context, b));
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
        public void WriteGeneralizedTime(DateTime time)
        {
            string time_str = time.ToUniversalTime().ToString("yyyyMMddHHmmssZ");
            _writer.WriteUniversalValue(false, UniversalTag.GeneralizedTime, Encoding.ASCII.GetBytes(time_str));
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
    }
}
