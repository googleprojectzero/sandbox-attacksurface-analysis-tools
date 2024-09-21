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

using NtApiDotNet.Win32.Security.Native;

namespace NtApiDotNet.Win32.Security.Authentication.Logon
{
    /// <summary>
    /// Class to represent a MSV1_0_LM20_LOGON credentials structure.
    /// </summary>
    public sealed class NtlmNetworkLogonCredentials : NtlmLm20LogonCredentials
    {
        /// <summary>
        /// Parameter control flags.
        /// </summary>
        public NtlmNetworkLogonParameterControlFlags ParameterControl { get; set; }

        private protected override MSV1_0_LM20_LOGON GetBaseStruct()
        {
            return new MSV1_0_LM20_LOGON()
            {
                MessageType = MSV1_0_LOGON_SUBMIT_TYPE.MsV1_0NetworkLogon,
                ParameterControl = (int)ParameterControl
            };
        }
    }
}
