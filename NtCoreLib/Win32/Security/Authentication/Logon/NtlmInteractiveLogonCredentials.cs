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

using NtCoreLib.Native.SafeBuffers;
using NtCoreLib.Utilities.Collections;
using NtCoreLib.Win32.Security.Interop;
using System;
using System.Runtime.InteropServices;
using System.Security;

namespace NtCoreLib.Win32.Security.Authentication.Logon;

/// <summary>
/// Class to represent a MSV1_0_INTERACTIVE_LOGON credential buffer.
/// </summary>
public sealed class NtlmInteractiveLogonCredentials : ILsaLogonCredentials, ILsaLogonCredentialsSerializable
{
    /// <summary>
    /// The logon domain name.
    /// </summary>
    public string LogonDomainName { get; set; }
    /// <summary>
    /// The logon user name.
    /// </summary>
    public string UserName { get; set; }
    /// <summary>
    /// The logon password.
    /// </summary>
    public SecureString Password { get; set; }
    
    /// <summary>
    /// Constructor
    /// </summary>
    /// <param name="credentials">The user's credentials.</param>
    public NtlmInteractiveLogonCredentials(UserCredentials credentials)
    {
        if (credentials is null)
        {
            throw new ArgumentNullException(nameof(credentials));
        }

        LogonDomainName = credentials.Domain;
        UserName = credentials.UserName;
        Password = credentials.Password;
    }

    private void PopulateLogon(LsaBufferBuilder<MSV1_0_INTERACTIVE_LOGON> builder, bool relative)
    {
        builder.AddUnicodeString(nameof(MSV1_0_INTERACTIVE_LOGON.LogonDomainName), LogonDomainName, relative);
        builder.AddUnicodeString(nameof(MSV1_0_INTERACTIVE_LOGON.UserName), UserName, relative);
        builder.AddUnicodeString(nameof(MSV1_0_INTERACTIVE_LOGON.Password), Password, relative);
    }

    private SafeBufferGeneric ToBuffer(bool relative)
    {
        var builder = new MSV1_0_INTERACTIVE_LOGON()
        {
            MessageType = MSV1_0_LOGON_SUBMIT_TYPE.MsV1_0InteractiveLogon
        }.ToBuilder();
        PopulateLogon(builder, relative);
        return builder.ToBuffer();
    }

    byte[] ILsaLogonCredentialsSerializable.ToArray()
    {
        using var buffer = ToBuffer(true);
        return buffer.ToArray();
    }

    string ILsaLogonCredentials.AuthenticationPackage => AuthenticationPackage.NTLM_NAME;

    SafeBuffer ILsaLogonCredentials.ToBuffer(DisposableList list)
    {
        return ToBuffer(false);
    }
}
