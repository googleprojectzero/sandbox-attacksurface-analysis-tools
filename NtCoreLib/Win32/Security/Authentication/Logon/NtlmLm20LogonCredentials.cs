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

using NtCoreLib.Utilities.Collections;
using NtCoreLib.Win32.Security.Interop;
using System;
using System.Runtime.InteropServices;

namespace NtCoreLib.Win32.Security.Authentication.Logon;

/// <summary>
/// Class to represent a MSV1_0_LM20_LOGON credentials structure.
/// </summary>
public class NtlmLm20LogonCredentials : ILsaLogonCredentials
{
    /// <summary>
    /// Logon domain name.
    /// </summary>
    public string LogonDomainName { get; set; }

    /// <summary>
    /// Logon user name.
    /// </summary>
    public string UserName { get; set; }

    /// <summary>
    /// Workstation name.
    /// </summary>
    public string Workstation { get; set; }

    /// <summary>
    /// Challenge to client. Should be 8 bytes in size.
    /// </summary>
    public byte[] ChallengeToClient { get; set; }

    /// <summary>
    /// Case sensitive challenge response.
    /// </summary>
    public byte[] CaseSensitiveChallengeResponse;

    /// <summary>
    /// Case insensitive challenge response.
    /// </summary>
    public byte[] CaseInsensitiveChallengeResponse;

    private protected virtual MSV1_0_LM20_LOGON GetBaseStruct()
    {
        return new MSV1_0_LM20_LOGON()
        {
            MessageType = MSV1_0_LOGON_SUBMIT_TYPE.MsV1_0Lm20Logon
        };
    }

    string ILsaLogonCredentials.AuthenticationPackage => AuthenticationPackage.NTLM_NAME;

    SafeBuffer ILsaLogonCredentials.ToBuffer(DisposableList list)
    {
        if (ChallengeToClient == null || ChallengeToClient.Length != 8)
            throw new ArgumentException("Invalid challenge to client.", nameof(ChallengeToClient));

        var base_struct = GetBaseStruct();
        base_struct.ChallengeToClient = ChallengeToClient;
        var builder = base_struct.ToBuilder();
        builder.AddUnicodeString(nameof(MSV1_0_LM20_LOGON.LogonDomainName), LogonDomainName);
        builder.AddUnicodeString(nameof(MSV1_0_LM20_LOGON.UserName), UserName);
        builder.AddUnicodeString(nameof(MSV1_0_LM20_LOGON.Workstation), Workstation);
        builder.AddAnsiString(nameof(MSV1_0_LM20_LOGON.CaseSensitiveChallengeResponse), CaseSensitiveChallengeResponse);
        builder.AddAnsiString(nameof(MSV1_0_LM20_LOGON.CaseInsensitiveChallengeResponse), CaseInsensitiveChallengeResponse);

        return builder.ToBuffer();
    }
}
