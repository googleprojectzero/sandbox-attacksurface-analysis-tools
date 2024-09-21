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

using NtApiDotNet.Win32.Security.Authentication.Logon;
using NtApiDotNet.Win32.Security.Native;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace NtApiDotNet.Win32.Security.Authentication.Ntlm
{
    /// <summary>
    /// Utilities for NTLM authentication.
    /// </summary>
    public static class NtlmUtils
    {
        /// <summary>
        /// Get a LM20 server challenge from the NTLM package.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>A NTLM server challenge.</returns>
        public static NtResult<byte[]> GetLm20ChallengeRequest(bool throw_on_error)
        {
            using (var handle = LsaLogonHandle.Connect())
            {
                using (var buffer = ((int)MSV1_0_PROTOCOL_MESSAGE_TYPE.MsV1_0Lm20ChallengeRequest).ToBuffer())
                {
                    using (var result = handle.LsaCallAuthenticationPackage(AuthenticationPackage.NTLM_NAME, buffer, throw_on_error))
                    {
                        if (!result.IsSuccess)
                            return result.Cast<byte[]>();
                        if (!result.Result.Status.IsSuccess())
                            return result.Result.Status.CreateResultFromError<byte[]>(throw_on_error);
                        return result.Result.Buffer.ReadBytes(4, 8).CreateResult();
                    }
                }
            }
        }

        /// <summary>
        /// Get a LM20 server challenge from the NTLM package.
        /// </summary>
        /// <returns>A NTLM server challenge.</returns>
        public static byte[] GetLm20ChallengeRequest()
        {
            return GetLm20ChallengeRequest(true).Result;
        }
    }
}
