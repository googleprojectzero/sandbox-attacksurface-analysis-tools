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
using System;

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos
{
    /// <summary>
    /// Class to represent a Kerberos time.
    /// </summary>
    public sealed class KerberosTime : IDERObject
    {
        #region Public Properties
        /// <summary>
        /// The Kerberos time as a string.
        /// </summary>
        public string Value { get; }

        /// <summary>
        /// Specify the maximum kerberos time.
        /// </summary>
        public static KerberosTime MaximumTime => new KerberosTime("20370913024805Z");

        /// <summary>
        /// Get current time as a kerberos time.
        /// </summary>
        public static KerberosTime Now => new KerberosTime(DateTime.Now);
        #endregion

        #region Constructors

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="time">The time as a string.</param>
        /// <remarks>This constructor doesn't validate the time string. Use the DateTime constructor to avoid mistakes.</remarks>
        public KerberosTime(string time)
        {
            Value = time;
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="time">The time as a date time.</param>
        public KerberosTime(DateTime time)
        {
            Value = DERUtils.ConvertGeneralizedTime(time);
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Get the kerberos time as a DateTime structure.
        /// </summary>
        /// <param name="usec">Optional usecs.</param>
        /// <returns>The kerberos time as a DateTime.</returns>
        public DateTime ToDateTime(int? usec = null)
        {
            if (DERUtils.TryParseGeneralizedTime(Value, out DateTime time))
            {
                return time.AddMilliseconds((usec ?? 0) / 1000);
            }
            return DateTime.MinValue;
        }

        /// <summary>
        /// Convert to a string.
        /// </summary>
        /// <returns>The time as a string.</returns>
        public override string ToString()
        {
            return Value;
        }
        #endregion

        #region IDERObject Implementation.
        void IDERObject.Write(DERBuilder builder)
        {
            builder.WriteGeneralizedTime(Value);
        }
        #endregion
    }
}
