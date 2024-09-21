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

using NtCoreLib.Win32.Security.Authentication;
using NtCoreLib.Win32.Security.Authentication.Kerberos;
using NtCoreLib.Win32.Security.Authentication.Kerberos.Client;
using NtCoreLib.Win32.Security.Authentication.Kerberos.Server;
using System;
using System.Management.Automation;

namespace NtObjectManager.Utils.Kerberos;

/// <summary>
/// Class to implement a KDC proxy using PowerShell.
/// </summary>
internal class PSKerberosKDCProxy : KerberosKDCProxy
{
    private readonly ScriptBlock _handle_request;
    private readonly ScriptBlock _handle_reply;
    private readonly ScriptBlock _handle_error;

    /// <summary>
    /// Constructor.
    /// </summary>
    /// <param name="listener">Server listener.</param>
    /// <param name="client_transport">Client transport.</param>
    /// <param name="handle_request">Script block to handle the request.</param>
    /// <param name="handle_reply">Script block to handle the reply.</param>
    /// <param name="handle_error">Script block to handle an error.</param>
    public PSKerberosKDCProxy(IKerberosKDCServerListener listener, IKerberosKDCClientTransport client_transport, 
        ScriptBlock handle_request, ScriptBlock handle_reply, ScriptBlock handle_error) 
        : base(listener, client_transport)
    {
        _handle_request = handle_request;
        _handle_reply = handle_reply;
        _handle_error = handle_error;
    }

    private static byte[] GetGenericError()
    {
        return KerberosErrorAuthenticationToken.Create(KerberosTime.Now, 0, KerberosErrorType.GENERIC, "UNKNOWN",
                new KerberosPrincipalName(KerberosNameType.SRV_INST, "UNKNOWN"),
                KerberosTime.Now).ToArray();
    }

    private void WriteError(Exception ex)
    {
        if (_handle_error != null)
        {
            PSUtils.InvokeWithArg(_handle_error, ex);
        }
    }

    /// <summary>
    /// Handle a request.
    /// </summary>
    /// <param name="request">The request to handle.</param>
    /// <returns>The reply.</returns>
    protected override byte[] HandleRequest(byte[] request)
    {
        try
        {
            if (_handle_request != null)
            {
                if (!KerberosKDCRequestAuthenticationToken.TryParse(request, out KerberosKDCRequestAuthenticationToken kdc_request))
                {
                    throw new ArgumentException("Invalid KDC request token.");
                }
                var handled_token = PSUtils.InvokeWithArg<AuthenticationToken>(_handle_request, default, kdc_request);
                if (handled_token is KerberosErrorAuthenticationToken)
                {
                    return handled_token.ToArray();
                }
                else if (handled_token is KerberosKDCRequestAuthenticationToken)
                {
                    request = handled_token.ToArray();
                }
                // Continue with anything else.
            }

            var reply = base.HandleRequest(request);
            if (_handle_reply == null)
                return reply;

            AuthenticationToken reply_token;
            if (KerberosKDCReplyAuthenticationToken.TryParse(reply, out KerberosKDCReplyAuthenticationToken kdc_reply))
            {
                reply_token = kdc_reply;
            }
            else if (KerberosErrorAuthenticationToken.TryParse(reply, out KerberosErrorAuthenticationToken err_reply))
            {
                reply_token = err_reply;
            }
            else
            {
                return reply;
            }

            var result = PSUtils.InvokeWithArg<AuthenticationToken>(_handle_reply, default, reply_token);
            if (result != null)
                reply_token = result;

            // Ensure error token is not GSSAPI wrapped.
            if (reply_token is KerberosErrorAuthenticationToken err_token)
                reply_token = err_token.Unwrap();

            return reply_token.ToArray();
        }
        catch(Exception ex)
        {
            WriteError(ex);
            return GetGenericError();
        }
    }
}
