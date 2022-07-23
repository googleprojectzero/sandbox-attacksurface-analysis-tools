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
using System.IO;

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos
{
    /// <summary>
    /// Type of last request.
    /// </summary>
    public enum KerberosLastRequestType
    {
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
        None = 0,
        LastTGTRequest = 1,
        LastInitialRequest = 2,
        NewestTGT = 3,
        LastRenewel = 4,
        LastRequest = 5,
        PasswordExpiry = 6,
        AccountExpiry = 7,
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
    }

    /// <summary>
    /// Kerberos last request time.
    /// </summary>
    public sealed class KerberosLastRequest : IDERObject
    {
        /// <summary>
        /// Last request type.
        /// </summary>
        public KerberosLastRequestType LastRequestType { get; }

        /// <summary>
        /// Last request time.
        /// </summary>
        public KerberosTime LastRequestTime { get; }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="last_request_type">The type of the last request.</param>
        /// <param name="last_request_time">The time of the last request.</param>
        public KerberosLastRequest(KerberosLastRequestType last_request_type, KerberosTime last_request_time)
        {
            LastRequestType = last_request_type;
            LastRequestTime = last_request_time ?? throw new System.ArgumentNullException(nameof(last_request_time));
        }

        internal static KerberosLastRequest Parse(DERValue value)
        {
            if (!value.CheckSequence() || !value.HasChildren())
            {
                throw new InvalidDataException();
            }

            KerberosLastRequestType last_request_type = KerberosLastRequestType.None;
            KerberosTime last_request_time = KerberosTime.Now;

            foreach (var next in value.Children)
            {
                if (next.Type != DERTagType.ContextSpecific)
                    throw new InvalidDataException();
                switch (next.Tag)
                {
                    case 0:
                        last_request_type = (KerberosLastRequestType)next.ReadChildInteger();
                        break;
                    case 1:
                        last_request_time = next.ReadChildKerberosTime();
                        break;
                    default:
                        throw new InvalidDataException();
                }
            }

            return new KerberosLastRequest(last_request_type, last_request_time);
        }

        void IDERObject.Write(DERBuilder builder)
        {
            using (var seq = builder.CreateSequence())
            {
                seq.WriteContextSpecific(0, LastRequestType);
                seq.WriteContextSpecific(1, LastRequestTime);
            }
        }
    }
}
