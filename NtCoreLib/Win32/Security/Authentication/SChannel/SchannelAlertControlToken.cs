//  Copyright 2021 Google Inc. All Rights Reserved.
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

namespace NtApiDotNet.Win32.Security.Authentication.Schannel
{
    /// <summary>
    /// Class to represent an Schannel alert control token.
    /// </summary>
    public sealed class SchannelAlertControlToken : SchannelControlToken
    {
        private const int SCHANNEL_ALERT = 2;
        private readonly SchannelAlertType _type;
        private readonly SchannelAlertNumber _number;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="type">The alert type.</param>
        /// <param name="number">The alert number.</param>
        public SchannelAlertControlToken(SchannelAlertType type, SchannelAlertNumber number)
        {
            _type = type;
            _number = number;
        }

        private protected override void WriteBuffer(DataWriter writer)
        {
            writer.Write(SCHANNEL_ALERT);
            writer.Write((int)_type);
            writer.Write((int)_number);
        }
    }
}
