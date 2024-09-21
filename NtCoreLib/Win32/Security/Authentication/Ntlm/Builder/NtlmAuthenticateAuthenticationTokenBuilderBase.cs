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

using System;
using System.IO;

namespace NtCoreLib.Win32.Security.Authentication.Ntlm.Builder;

/// <summary>
/// Base class for an NTLM authentication authentication token builder.
/// </summary>
public abstract class NtlmAuthenticateAuthenticationTokenBuilderBase : NtlmAuthenticationTokenBuilder
{
    #region Public Properties
    /// <summary>
    /// Domain name.
    /// </summary>
    public string Domain { get; set; }
    /// <summary>
    /// Workstation name.
    /// </summary>
    public string Workstation { get; set; }
    /// <summary>
    /// Username.
    /// </summary>
    public string UserName { get; set; }
    /// <summary>
    /// NTLM version.
    /// </summary>
    public Version Version { get; set; }
    /// <summary>
    /// Encrypted session key.
    /// </summary>
    public byte[] EncryptedSessionKey { get; set; }
    /// <summary>
    /// LM Challenge Response.
    /// </summary>
    public byte[] LmChallengeResponse { get; set; }
    /// <summary>
    /// Message integrity code.
    /// </summary>
    public byte[] MessageIntegrityCode { get; set; }
    #endregion

    #region Private Members
    private const int BASE_OFFSET = 72;

    private protected NtlmAuthenticateAuthenticationTokenBuilderBase() 
        : base(NtlmMessageType.Authenticate)
    {
    }

    private protected abstract byte[] GetNtChallenge();

    private protected override byte[] GetBytes()
    {
        var flags = Flags & ~(NtlmNegotiateFlags.KeyExchange | NtlmNegotiateFlags.Version | 
            NtlmNegotiateFlags.TargetTypeDomain | NtlmNegotiateFlags.TargetTypeServer | NtlmNegotiateFlags.TargetTypeShare);
        bool unicode = flags.HasFlagSet(NtlmNegotiateFlags.Unicode);
        if (EncryptedSessionKey != null && EncryptedSessionKey.Length > 0)
            flags |= NtlmNegotiateFlags.KeyExchange;
        if (Version != null)
            flags |= NtlmNegotiateFlags.Version;

        byte[] mic = MessageIntegrityCode ?? Array.Empty<byte>();
        if (mic.Length != 0 && mic.Length < 16)
                throw new ArgumentException("MIC must be 16 bytes in size if present.", nameof(MessageIntegrityCode));
        int base_offset = BASE_OFFSET + mic.Length;

        MemoryStream stm = new();
        BinaryWriter writer = new(stm);
        MemoryStream payload = new();
        writer.WriteBinary(LmChallengeResponse, base_offset, payload);
        writer.WriteBinary(GetNtChallenge(), base_offset, payload);
        writer.WriteString(Domain, unicode, base_offset, payload);
        writer.WriteString(UserName, unicode, base_offset, payload);
        writer.WriteString(Workstation, unicode, base_offset, payload);
        writer.WriteBinary(EncryptedSessionKey, base_offset, payload);
        writer.Write((uint)flags);
        writer.WriteVersion(Version);
        writer.Write(mic);
        writer.Write(payload.ToArray());
        return stm.ToArray();
    }
    #endregion
}
