//  Copyright 2022 Google LLC. All Rights Reserved.
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

using NtApiDotNet.Utilities.ASN1;
using NtApiDotNet.Utilities.ASN1.Builder;
using NtApiDotNet.Utilities.Reflection;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos
{
    /// <summary>
    /// Defined types for KerberosTypedData extended errors.
    /// </summary>
    public enum KerberosTypedDataType
    {
        [SDKName("TD_DH_PARAMETERS_TYPE")]
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
        DHParametersType = 109,
        [SDKName("TD_MUST_USE_USER2USER")]
        MustUseUser2User = -128,
        [SDKName("TD_EXTENDED_ERROR")]
        ExtendedError = -129
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
    }

    /// <summary>
    /// Class to represent a Kerberos TYPED-DATA structure.
    /// </summary>
    public sealed class KerberosTypedData : IDERObject
    {
        /// <summary>
        /// The type of the typed data.
        /// </summary>
        public KerberosTypedDataType Type { get; }

        /// <summary>
        /// The associated data.
        /// </summary>
        public byte[] Data { get; }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="type">The type of the data.</param>
        /// <param name="data"></param>
        public KerberosTypedData(KerberosTypedDataType type, byte[] data)
        {
            Type = type;
            Data = data ?? Array.Empty<byte>();
        }

        private static KerberosTypedData Parse(DERValue value)
        {
            if (!value.CheckSequence())
                throw new InvalidDataException();
            KerberosTypedDataType data_type = 0;
            byte[] data = null;
            foreach (var next in value.Children)
            {
                if (next.Type != DERTagType.ContextSpecific)
                    throw new InvalidDataException();

                switch (next.Tag)
                {
                    case 0:
                        data_type = (KerberosTypedDataType)next.ReadChildInteger();
                        break;
                    case 1:
                        data = next.ReadChildOctetString();
                        break;
                    default:
                        throw new InvalidDataException();
                }
            }

            return new KerberosTypedData(data_type, data);
        }

        internal static bool TryParse(byte[] error_data, out List<KerberosTypedData> typed_data)
        {
            typed_data = null;
            try
            {
                DERValue[] values = DERParser.ParseData(error_data, 0);
                if (values.Length != 1 || !values[0].CheckSequence())
                    return false;
                typed_data = values[0].Children.Select(v => Parse(v)).ToList();
                return true;
            }
            catch
            {
            }
            return false;
        }

        void IDERObject.Write(DERBuilder builder)
        {
            using (var seq = builder.CreateSequence())
            {
                seq.WriteContextSpecific(0, (int)Type);
                seq.WriteContextSpecific(1, Data);
            }
        }
    }
}
