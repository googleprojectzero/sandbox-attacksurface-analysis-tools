//  Copyright 2016 Google Inc. All Rights Reserved.
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
using System;
using System.Management.Automation;
using System.Collections.Generic;
using System.Linq;
using NtCoreLib.Security.Authorization;
using NtCoreLib.Security.Token;
using NtCoreLib.Security;

namespace NtObjectManager.Cmdlets.Object;

/// <summary>
/// <para type="synopsis">Create a new NT token.</para>
/// <para type="description">This cmdlet creates a new NT token kernel APIs. It needs SeCreateTokenPrivilege to succeed.</para>
/// </summary>
/// <example>
///   <code>$token = New-NtToken -User "SY"</code>
///   <para>Create a new LocalSystem token with no groups or privileges.</para>
/// </example>
/// <example>
///   <code>$token = New-NtToken -User "SY" -Groups "BA","WD" -Privileges SeDebugPrivilege,SeImpersonatePrivilege</code>
///   <para>Create a new LocalSystem token with two groups and two privileges.</para>
/// </example>
/// <para type="link">about_ManagingNtObjectLifetime</para>
[Cmdlet(VerbsCommon.New, "NtToken", DefaultParameterSetName = "FromGroup")]
[OutputType(typeof(NtToken))]
public sealed class NewNtTokenCmdlet : NtObjectBaseCmdletWithAccess<TokenAccessRights>
{
    /// <summary>
    /// <para type="description">Specify the user SID.</para>
    /// </summary>
    [Parameter(Mandatory = true)]
    public Sid User { get; set; }

    /// <summary>
    /// <para type="description">Specify a list of groups.</para>
    /// </summary>
    [Parameter(ParameterSetName = "FromGroup")]
    [Alias("Groups")]
    public Sid[] Group { get; set; }

    /// <summary>
    /// <para type="description">Specify a list of groups. To add an Integrity Level specify an IL group.</para>
    /// </summary>
    [Parameter(ParameterSetName = "FromUserGroup")]
    public UserGroup[] UserGroup { get; set; }

    /// <summary>
    /// <para type="description">Specify a list of privileges.</para>
    /// </summary>
    [Parameter(ParameterSetName = "FromGroup")]
    [Alias("Privileges")]
    public TokenPrivilegeValue[] Privilege { get; set; }

    /// <summary>
    /// <para type="description">Specify a list of privileges with full details of the flags.</para>
    /// </summary>
    [Parameter(ParameterSetName = "FromUserGroup")]
    public TokenPrivilege[] UserPrivilege { get; set; }

    /// <summary>
    /// <para type="description">Specify an authentication ID.</para>
    /// </summary>
    [Parameter]
    public Luid AuthenticationId { get; set; }

    /// <summary>
    /// <para type="description">Specify the token type.</para>
    /// </summary>
    [Parameter]
    public TokenType TokenType { get; set; }

    /// <summary>
    /// <para type="description">Specify the token expiration time.</para>
    /// </summary>
    [Parameter]
    public DateTime ExpirationTime { get; set; }

    /// <summary>
    /// <para type="description">Specify the token's default ACL.</para>
    /// </summary>
    [Parameter]
    public Acl DefaultAcl { get; set; }

    /// <summary>
    /// <para type="description">Specify the token's integrity level.</para>
    /// </summary>
    [Parameter(ParameterSetName = "FromGroup")]
    public TokenIntegrityLevel IntegrityLevel { get; set; }

    /// <summary>
    /// <para type="description">Specify a list of device groups.</para>
    /// </summary>
    [Parameter]
    public UserGroup[] DeviceGroup { get; set; }

    /// <summary>
    /// <para type="description">Specify a list of device attributes.</para>
    /// </summary>
    [Parameter]
    public ClaimSecurityAttribute[] DeviceAttribute { get; set; }

    /// <summary>
    /// <para type="description">Specify a list of user attributes.</para>
    /// </summary>
    [Parameter]
    public ClaimSecurityAttribute[] UserAttribute { get; set; }

    /// <summary>
    /// <para type="description">Specify token mandatory policy.</para>
    /// </summary>
    [Parameter]
    public TokenMandatoryPolicy? MandatoryPolicy { get; set; }

    /// <summary>
    /// Determine if the cmdlet can create objects.
    /// </summary>
    /// <returns>True if objects can be created.</returns>
    protected override bool CanCreateDirectories()
    {
        return false;
    }

    private IEnumerable<UserGroup> GetGroups()
    {
        if (ParameterSetName == "FromUserGroup")
        {
            return UserGroup;
        }

        List<UserGroup> groups = Group.Select(g => new UserGroup(g, GroupAttributes.Enabled | GroupAttributes.EnabledByDefault | GroupAttributes.Mandatory)).ToList();
        groups.Add(new UserGroup(NtSecurity.GetIntegritySid(IntegrityLevel), GroupAttributes.Integrity | GroupAttributes.IntegrityEnabled));
        return groups;
    }

    private IEnumerable<TokenPrivilege> GetPrivileges()
    {
        if (ParameterSetName == "FromUserGroup")
        {
            return UserPrivilege;
        }
        return Privilege.Select(p => new TokenPrivilege(p, PrivilegeAttributes.EnabledByDefault | PrivilegeAttributes.Enabled));
    }

    /// <summary>
    /// Method to create an object from a set of object attributes.
    /// </summary>
    /// <param name="obj_attributes">The object attributes to create/open from.</param>
    /// <returns>The newly created object.</returns>
    protected override object CreateObject(ObjectAttributes obj_attributes)
    {
        if (!NtToken.EffectivePrivilegeCheck(TokenPrivilegeValue.SeCreateTokenPrivilege))
        {
            WriteWarning("SeCreateTokenPrivilege is not enabled.");
        }
        return NtToken.Create(Access, obj_attributes, TokenType, AuthenticationId, ExpirationTime.ToFileTimeUtc(), new UserGroup(User, GroupAttributes.Owner),
            GetGroups(), GetPrivileges(), UserAttribute,
            DeviceAttribute, DeviceGroup, MandatoryPolicy, User, User, DefaultAcl, "NT.NET");
    }

    /// <summary>
    /// Constructor.
    /// </summary>
    public NewNtTokenCmdlet()
    {
        AuthenticationId = NtToken.LocalSystemAuthId;
        TokenType = TokenType.Primary;
        ExpirationTime = DateTime.Now.AddYears(10);
        Group = new Sid[0];
        Privilege = new TokenPrivilegeValue[0];
        UserPrivilege = new TokenPrivilege[0];
        UserGroup = new UserGroup[0];
        DefaultAcl = new Acl();
        DefaultAcl.AddAccessAllowedAce(GenericAccessRights.GenericAll, AceFlags.None, "SY");
        DefaultAcl.AddAccessAllowedAce(GenericAccessRights.GenericAll, AceFlags.None, "BA");
        IntegrityLevel = TokenIntegrityLevel.System;
        SecurityQualityOfService = new SecurityQualityOfService(SecurityImpersonationLevel.Anonymous, SecurityContextTrackingMode.Static, false);
    }
}
