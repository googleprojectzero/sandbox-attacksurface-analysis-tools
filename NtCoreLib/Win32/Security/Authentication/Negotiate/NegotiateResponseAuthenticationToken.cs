//  Copyright 2020 Google Inc. All Rights Reserved.
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

using NtCoreLib.Utilities.ASN1;
using NtCoreLib.Utilities.ASN1.Builder;
using System.Text;

namespace NtCoreLib.Win32.Security.Authentication.Negotiate;

/// <summary>
/// State of the Negotiate state.
/// </summary>
public enum NegotiateAuthenticationState
{
    /// <summary>
    /// Negotiate completed.
    /// </summary>
    Completed = 0,
    /// <summary>
    /// Negotiate incomplete.
    /// </summary>
    Incomplete = 1,
    /// <summary>
    /// Negotiate rejected.
    /// </summary>
    Reject = 2,
    /// <summary>
    /// Request Message Integrity Code.
    /// </summary>
    RequestMIC = 3
}

/// <summary>
/// Class to represent the negTokenResp message in SPNEGO.
/// </summary>
public sealed class NegotiateResponseAuthenticationToken : NegotiateAuthenticationToken
{
    /// <summary>
    /// Supported mechanism for the token, optional.
    /// </summary>
    public string SupportedMechanism { get; }

    /// <summary>
    /// Current state of the negotiation.
    /// </summary>
    public NegotiateAuthenticationState? State { get; }

    /// <summary>
    /// Create a NegTokenInit token.
    /// </summary>
    /// <param name="state">The authentication state.</param>
    /// <param name="mech_type">The authentication mechanisms we support.</param>
    /// <param name="response_token">An initial authentication token.</param>
    /// <param name="mech_list_mic">Optional mechanism list MIC.</param>
    /// <param name="wrap_gssapi">Specify to wrap the token is a GSS-API wrapper.</param>
    /// <returns>The response token.</returns>
    public static NegotiateResponseAuthenticationToken Create(NegotiateAuthenticationState? state,
        string mech_type = null, AuthenticationToken response_token = null, byte[] mech_list_mic = null,
        bool wrap_gssapi = false)
    {
        DERBuilder builder = new();
        using (var context = builder.CreateContextSpecific(1))
        {
            using var seq = context.CreateSequence();
            seq.WriteContextSpecific(0, b => b.WriteEnumerated(state));
            if (!string.IsNullOrEmpty(mech_type))
            {
                seq.WriteContextSpecific(1, b => b.WriteObjectId(mech_type));
            }
            seq.WriteContextSpecific(2, response_token?.ToArray());
            seq.WriteContextSpecific(3, mech_list_mic);
        }
        byte[] token = wrap_gssapi ? GSSAPIUtils.Wrap(OIDValues.SPNEGO, builder.ToArray()) : builder.ToArray();
        return (NegotiateResponseAuthenticationToken)Parse(token);
    }

    private protected override void FormatData(StringBuilder builder)
    {
        if (!string.IsNullOrWhiteSpace(SupportedMechanism))
        {
            builder.AppendLine($"Supported Mech  : {SupportedMechanism} - {OIDValues.ToString(SupportedMechanism)}");
        }
        if (State.HasValue)
        {
            builder.AppendLine($"State           : {State.Value}");
        }
    }

    internal NegotiateResponseAuthenticationToken(byte[] data, 
        string supported_mech, NegotiateAuthenticationState? state, AuthenticationToken token, byte[] mic)
        : base(data, token, mic)
    {
        SupportedMechanism = supported_mech;
        State = state;
    }
}
