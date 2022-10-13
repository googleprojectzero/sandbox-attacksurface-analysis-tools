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

using NtApiDotNet.Utilities.Data;
using System;
using System.Collections.Generic;
using System.Text;

namespace NtApiDotNet.Win32.Security.Authentication.NegoEx
{
    /// <summary>
    /// Class for a NEGOEX ALERT_MESSAGE message.
    /// </summary>
    public sealed class NegoExMessageAlert : NegoExMessage
    {
        /// <summary>
        /// The authentication scheme selected.
        /// </summary>
        public Guid AuthScheme { get; }

        /// <summary>
        /// The associated error code.
        /// </summary>
        public NtStatus ErrorCode { get; }

        /// <summary>
        /// The checksum for the message.
        /// </summary>
        public IReadOnlyList<NegoExAlert> Alerts { get; }

        private NegoExMessageAlert(NegoExMessageHeader header, Guid auth_scheme, NtStatus error_code, List<NegoExAlert> alerts) : base(header)
        {
            AuthScheme = auth_scheme;
            ErrorCode = error_code;
            Alerts = alerts.AsReadOnly();
        }

        internal static NegoExMessageAlert Parse(NegoExMessageHeader header, byte[] data)
        {
            DataReader reader = new DataReader(data);
            reader.Position = NegoExMessageHeader.HEADER_SIZE;
            Guid auth_scheme = reader.ReadGuid();
            NtStatus error_code = reader.ReadUInt32Enum<NtStatus>();
            int alert_ofs = reader.ReadInt32();
            int alert_count = reader.ReadUInt16();
            List<NegoExAlert> alerts = new List<NegoExAlert>();
            if (alert_count > 0)
            {
                reader.Position = alert_ofs;
                for (int i = 0; i < alert_count; ++i)
                {
                    int type = reader.ReadInt32();
                    byte[] value = ReadByteVector(reader, data);
                    alerts.Add(new NegoExAlert(type, value));
                }
            }

            return new NegoExMessageAlert(header, auth_scheme, error_code, alerts);
        }

        private protected override void InnerFormat(StringBuilder builder)
        {
            builder.AppendLine($"Auth Scheme      : {FormatAuthScheme(AuthScheme)}");
            builder.AppendLine($"Error Code       : {ErrorCode}");
            for (int i = 0; i < Alerts.Count; ++i)
            {
                builder.AppendLine($"Alert {0} Type   : {Alerts[i].Type}");
                builder.AppendLine($"Alert {0} Value  : {NtObjectUtils.ToHexString(Alerts[i].Value)}");
            }
        }
    }
}
