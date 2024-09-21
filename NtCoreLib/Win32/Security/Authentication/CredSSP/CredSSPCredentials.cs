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

using NtCoreLib.Native.SafeBuffers;
using NtCoreLib.Utilities.Collections;
using NtCoreLib.Win32.Security.Authentication.Schannel;
using NtCoreLib.Win32.Security.Interop;
using System;
using System.Runtime.InteropServices;

namespace NtCoreLib.Win32.Security.Authentication.CredSSP;

/// <summary>
/// Credentials for the CredSSP package.
/// </summary>
/// <remarks>This is only needed if you must have both schannel and user credentials. Otherwise use UserCredentials or SchannelCredentials.</remarks>
public sealed class CredSSPCredentials : AuthenticationCredentials
{
    private readonly SchannelCredentials _schannel;
    private readonly AuthenticationCredentials _user;
    private readonly bool _redirect;

    /// <summary>
    /// Constructor.
    /// </summary>
    /// <param name="schannel">The credentials for the Schannel connection.</param>
    /// <param name="user">The credentials for the user.</param>
    /// <param name="redirect">Indicates that the credentials should be redirected.</param>
    public CredSSPCredentials(SchannelCredentials schannel, AuthenticationCredentials user, bool redirect)
    {
        _schannel = schannel ?? throw new ArgumentNullException(nameof(schannel));
        _user = user ?? throw new ArgumentNullException(nameof(user));
        _redirect = redirect;
    }

    /// <summary>
    /// Constructor.
    /// </summary>
    /// <param name="schannel">The credentials for the Schannel connection.</param>
    /// <param name="credentials">The credentials for the user.</param>
    public CredSSPCredentials(SchannelCredentials schannel, AuthenticationCredentials credentials) 
        : this(schannel, credentials, false)
    {
    }

    /// <summary>
    /// Constructor.
    /// </summary>
    /// <param name="credentials">The credentials for the user.</param>
    public CredSSPCredentials(AuthenticationCredentials credentials)
    {
        _user = credentials ?? throw new ArgumentNullException(nameof(credentials));
    }

    internal override SafeBuffer ToBuffer(DisposableList list, string package)
    {
        if (!AuthenticationPackage.CheckCredSSP(package) && !AuthenticationPackage.CheckTSSSP(package))
        {
            throw new ArgumentException("Can only use CredSSPCredentials for the CredSSP package.", nameof(package));
        }

        CREDSSP_CRED ret = new()
        {
            Type = CREDSSP_SUBMIT_TYPE.CredsspSubmitBufferBoth,
            pSchannelCred = list.AddBuffer(_schannel?.ToBuffer(list, package)),
            pSpnegoCred = list.AddBuffer(_user?.ToBuffer(list, package))
        };

        if (!AuthenticationPackage.CheckTSSSP(package) && !_redirect)
            return ret.ToBuffer();

        return new CREDSSP_CRED_EX()
        {
            Type = CREDSSP_SUBMIT_TYPE.CredsspCredEx,
            Version = 0,
            Flags = _redirect ? CredSspExFlags.Redirect : 0,
            Cred = ret
        }.ToBuffer();
    }
}
