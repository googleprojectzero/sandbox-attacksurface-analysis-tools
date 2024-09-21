//  Copyright 2017 Google Inc. All Rights Reserved.
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

using NtCoreLib;
using NtCoreLib.Security.Authorization;
using NtCoreLib.Security.Token;
using NtCoreLib.Win32.Security.Authorization;
using System.Collections.Generic;
using System.Linq;

namespace NtObjectManager.Cmdlets.Accessible;

/// <summary>
/// Information about a token.
/// </summary>
public class TokenInformation
{
    /// <summary>
    /// Token user.
    /// </summary>
    public Sid User { get; }

    /// <summary>
    /// Token user name.
    /// </summary>
    public string UserName => User.Name;

    /// <summary>
    /// Token integrity level
    /// </summary>
    public TokenIntegrityLevel IntegrityLevel { get; }

    /// <summary>
    /// Token type
    /// </summary>
    public TokenType TokenType { get; }

    /// <summary>
    /// Token impersonation level
    /// </summary>
    public SecurityImpersonationLevel ImpersonationLevel { get; }

    /// <summary>
    /// Token ID
    /// </summary>
    public Luid TokenId { get; }

    /// <summary>
    /// Get the authentication ID.
    /// </summary>
    public Luid AuthenticationId { get; }

    /// <summary>
    /// Get the origin authentication ID.
    /// </summary>
    public Luid Origin { get; }

    /// <summary>
    /// Elevated token
    /// </summary>
    public bool Elevated { get; }

    /// <summary>
    /// Restricted token
    /// </summary>
    public bool Restricted { get; }

    /// <summary>
    /// Write restricted token
    /// </summary>
    public bool WriteRestricted { get; }

    /// <summary>
    /// App container token
    /// </summary>
    public bool AppContainer { get; }

    /// <summary>
    /// App container SID (if an AppContainer)
    /// </summary>
    public Sid AppContainerSid { get; }

    /// <summary>
    /// Get the elevation type.
    /// </summary>
    public TokenElevationType ElevationType { get; }

    /// <summary>
    /// Low privilege AC
    /// </summary>
    public bool LowPrivilegeAppContainer { get; }

    /// <summary>
    /// The session ID of the token.
    /// </summary>
    public int SessionId { get; }

    /// <summary>
    /// Get token groups.
    /// </summary>
    public IEnumerable<UserGroup> Groups { get; }

    /// <summary>
    /// Get restricted SIDs.
    /// </summary>
    public IEnumerable<UserGroup> RestrictedSids { get; }

    /// <summary>
    /// Get capability SIDs.
    /// </summary>
    public IEnumerable<UserGroup> Capabilities { get; }

    /// <summary>
    /// Get privileges.
    /// </summary>
    public IEnumerable<TokenPrivilege> Privileges { get; }

    /// <summary>
    /// Whether the token is considered sandboxed.
    /// </summary>
    public bool Sandbox { get; }

    /// <summary>
    /// Get whether the token can be used for child processes.
    /// </summary>
    public bool NoChildProcess { get; }

    /// <summary>
    /// Get the token flags.
    /// </summary>
    public TokenFlags Flags { get; }

    /// <summary>
    /// Get the UI access flag.
    /// </summary>
    public bool UIAccess { get; }

    /// <summary>
    /// Get the token mandatory policy.
    /// </summary>
    public TokenMandatoryPolicy MandatoryPolicy { get; }

    /// <summary>
    /// Additonal information of where the token was sourced from
    /// </summary>
    public Dictionary<string, object> SourceData { get; }

    /// <summary>
    /// Overridden ToString.
    /// </summary>
    /// <returns>The information as a string.</returns>
    public override string ToString()
    {
        return $"User: {User}";
    }

    internal TokenInformation(NtToken token) 
        : this(token, null)
    {
    }

    internal TokenInformation(NtToken token, NtProcess process)
    {
        SourceData = new Dictionary<string, object>();
        TokenId = token.Id;
        AuthenticationId = token.AuthenticationId;
        Origin = token.Origin;
        Flags = token.Flags;
        User = token.User.Sid;
        IntegrityLevel = token.IntegrityLevel;
        TokenType = token.TokenType;
        ImpersonationLevel = token.ImpersonationLevel;
        AppContainer = token.AppContainer;
        AppContainerSid = token.AppContainerSid;
        Elevated = token.Elevated;
        ElevationType = token.ElevationType;
        Restricted = token.Restricted;
        WriteRestricted = token.WriteRestricted;
        LowPrivilegeAppContainer = token.LowPrivilegeAppContainer;
        SessionId = token.SessionId;
        Groups = token.Groups.ToList().AsReadOnly();
        RestrictedSids = token.RestrictedSids.ToList().AsReadOnly();
        Capabilities = token.Capabilities.ToList().AsReadOnly();
        Privileges = token.Privileges.ToList().AsReadOnly();
        Sandbox = token.IsSandbox;
        NoChildProcess = token.NoChildProcess;
        UIAccess = token.UIAccess;
        MandatoryPolicy = token.MandatoryPolicy;

        if (process != null)
        {
            SourceData["ProcessId"] = process.ProcessId;
            SourceData["Name"] = process.Name;
            SourceData["ImagePath"] = process.GetImageFilePath(false, false).GetResultOrDefault(string.Empty);
            SourceData["CommandLine"] = process.CommandLine;
            SourceData["NativeImagePath"] = process.GetImageFilePath(true, false).GetResultOrDefault(string.Empty);
        }
    }

    internal TokenInformation(AuthZContext context)
    {
        SourceData = new Dictionary<string, object>();
        User = context.User.Sid;
        IntegrityLevel = TokenIntegrityLevel.Medium;
        TokenType = TokenType.Impersonation;
        ImpersonationLevel = SecurityImpersonationLevel.Impersonation;
        Groups = context.Groups.ToList().AsReadOnly();
    }
}