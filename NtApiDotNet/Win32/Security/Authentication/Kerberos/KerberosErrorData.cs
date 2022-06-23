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
using NtApiDotNet.Utilities.Text;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos
{
    /// <summary>
    /// Type of Kerberos error data.
    /// </summary>
    public enum KerberosErrorDataType
    {
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
        [SDKName("KERB_AP_ERR_TYPE_SKEW_RECOVERY")]
        SkewRecovery = 2,
        [SDKName("KERB_ERR_TYPE_EXTENDED")]
        Extended = 3,
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
    }

    /// <summary>
    /// Represents MS specific KERB-ERROR-DATA structure.
    /// </summary>
    public class KerberosErrorData : IDERObject
    {
        /// <summary>
        /// The type of the error data.
        /// </summary>
        public KerberosErrorDataType DataType { get; }

        /// <summary>
        /// The raw data value.
        /// </summary>
        public byte[] DataValue { get; }

        private static KerberosErrorData Parse(KerberosErrorDataType data_type, byte[] data_value)
        {
            switch (data_type)
            {
                case KerberosErrorDataType.Extended:
                    if (KerberosErrorDataExtended.TryParse(data_value, out KerberosErrorData res))
                        return res;
                    break;
            }
            return new KerberosErrorData(data_type, data_value);
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="data_type">The type of error.</param>
        /// <param name="data_value">The error value.</param>
        public KerberosErrorData(KerberosErrorDataType data_type, byte[] data_value)
        {
            DataType = data_type;
            DataValue = data_value;
        }

        internal static KerberosErrorData Parse(byte[] error_data)
        {
            try
            {
                DERValue[] values = DERParser.ParseData(error_data, 0);
                if (values.Length != 1 || !values[0].CheckSequence())
                    return null;
                DERValue value = values[0];
                KerberosErrorDataType data_type = 0;
                byte[] data = null;
                foreach (var next in value.Children)
                {
                    if (next.Type != DERTagType.ContextSpecific)
                        break;
                        
                    switch (next.Tag)
                    {
                        case 1:
                            data_type = (KerberosErrorDataType)next.ReadChildInteger();
                            break;
                        case 2:
                            data = next.ReadChildOctetString();
                            break;
                        default:
                            data_type = 0;
                            break;
                    }
                }

                return Parse(data_type, data);
            }
            catch
            {
            }
            return null;
        }

        private protected virtual void FormatData(StringBuilder builder)
        {
            if (DataValue == null || DataValue.Length == 0)
                return;
            HexDumpBuilder hex = new HexDumpBuilder(true, true, true, true, 0);
            hex.Append(DataValue);
            hex.Complete();
            builder.AppendLine($"DataValue: {NtObjectUtils.ToHexString(DataValue)}");
        }

        /// <summary>
        /// Overridden ToString method.
        /// </summary>
        /// <returns>The error as a string.</returns>
        public override string ToString()
        {
            StringBuilder builder = new StringBuilder();
            builder.AppendLine($"<KerberosErrorData {DataType}>");
            FormatData(builder);
            return builder.ToString();
        }

        void IDERObject.Write(DERBuilder builder)
        {
            using (var seq = builder.CreateSequence())
            {
                seq.WriteContextSpecific(1, (int)DataType);
                seq.WriteContextSpecific(2, DataValue);
            }
        }
    }

    /// <summary>
    /// Kerberos error for KERB_ERR_TYPE_EXTENDED.
    /// </summary>
    public sealed class KerberosErrorDataExtended : KerberosErrorData
    {
        /// <summary>
        /// The NT status.
        /// </summary>
        public NtStatus Status { get; }

        /// <summary>
        /// The reserved field.
        /// </summary>
        public int Reserved { get; }

        /// <summary>
        /// The flags.
        /// </summary>
        public int Flags { get; }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="status">The NT status code.</param>
        /// <param name="reserved">The reserved value.</param>
        /// <param name="flags">The flags.</param>
        public KerberosErrorDataExtended(NtStatus status, int reserved, int flags) :
            this(BuildData(status, reserved, flags), status, reserved, flags)
        {
        }

        internal static bool TryParse(byte[] data, out KerberosErrorData result)
        {
            result = null;
            if (data == null)
                return false;
            if (data.Length < 12)
                return false;
            result = new KerberosErrorDataExtended(data,
                (NtStatus)BitConverter.ToUInt32(data, 0),
                BitConverter.ToInt32(data, 4),
                BitConverter.ToInt32(data, 8));
            return true;
        }

        private static byte[] BuildData(NtStatus status, int reserved, int flags)
        {
            MemoryStream stm = new MemoryStream();
            BinaryWriter writer = new BinaryWriter(stm);
            writer.Write((uint)status);
            writer.Write(reserved);
            writer.Write(flags);
            return stm.ToArray();
        }

        private protected override void FormatData(StringBuilder builder)
        {
            builder.AppendLine($"Status  : {Status}");
            builder.AppendLine($"Reserved: {Reserved}");
            builder.AppendLine($"Flags   : {Flags}");
        }

        private KerberosErrorDataExtended(byte[] data_value, NtStatus status, int reserved, int flags) 
            : base(KerberosErrorDataType.Extended, data_value)
        {
            Status = status;
            Reserved = reserved;
            Flags = flags;
        }
    }
}
