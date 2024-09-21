using NtCoreLib;
using NtCoreLib.Security;
using NtCoreLib.Security.Authorization;
using NtCoreLib.Security.Token;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Management.Automation;

namespace NtObjectManager.Cmdlets.Object;

/// <summary>
/// <para type="synopsis">Write manual security audit events.</para>
/// <para type="description">This cmdlet allows you to write manual audit events. You must be SeAuditPrivilege for this
/// to work.</para>
/// </summary>
/// <example>
///   <code>$on_close = Write-NtAudit -Open -SubsystemName "Subsystem" -SecurityDescriptor $sd -Name "ABC" -AccessGranted</code>
///   <para>Write an open object audit event.</para>
/// </example>
/// <example>
///   <code>$on_close = Write-NtAudit -Close -SubsystemName "Subsystem" -HandleId 1234 -GeneratedOnClose</code>
///   <para>Write a close object audit event.</para>
/// </example>
[Cmdlet(VerbsCommunications.Write, "NtAudit")]
public class WriteNtAuditCmdlet : PSCmdlet
{
    /// <summary>
    /// <para type="description">Specify the security descriptor for the object.</para>
    /// </summary>
    [Parameter(Mandatory = true, ParameterSetName = "OpenObject")]
    public SecurityDescriptor SecurityDescriptor { get; set; }

    /// <summary>
    /// <para type="description">Specify the name of the subsystem.</para>
    /// </summary>
    [Parameter(Mandatory = true)]
    public string SubsystemName { get; set; }

    /// <summary>
    /// <para type="description">Specify the handle ID.</para>
    /// </summary>
    [Parameter(ParameterSetName = "OpenObject")]
    [Parameter(ParameterSetName = "CloseObject")]
    [Parameter(ParameterSetName = "DeleteObject")]
    [Parameter(ParameterSetName = "PrivilegeObject")]
    public IntPtr HandleId { get; set; }

    /// <summary>
    /// <para type="description">Specify the name of the object type.</para>
    /// </summary>
    [Parameter(ParameterSetName = "OpenObject")]
    public string TypeName { get; set; }

    /// <summary>
    /// <para type="description">Specify the name of the object.</para>
    /// </summary>
    [Parameter(Mandatory = true, ParameterSetName = "OpenObject")]
    public string Name { get; set; }

    /// <summary>
    /// <para type="description">Specify the name of the service.</para>
    /// </summary>
    [Parameter(Mandatory = true, ParameterSetName = "PrivilegeService")]
    public string ServiceName { get; set; }

    /// <summary>
    /// <para type="description">Specify a token object for the audit event. If not specified then current effective token is used.</para>
    /// </summary>
    [Parameter(ParameterSetName = "OpenObject")]
    [Parameter(ParameterSetName = "PrivilegeObject")]
    [Parameter(ParameterSetName = "PrivilegeService")]
    public NtToken Token { get; set; }

    /// <summary>
    /// <para type="description">Specify the desired access.</para>
    /// </summary>
    [Parameter(ParameterSetName = "OpenObject")]
    [Parameter(ParameterSetName = "PrivilegeObject")]
    public AccessMask DesiredAccess { get; set; }

    /// <summary>
    /// <para type="description">Specify the granted access.</para>
    /// </summary>
    [Parameter(ParameterSetName = "OpenObject")]
    public AccessMask GrantedAccess { get; set; }

    /// <summary>
    /// <para type="description">Specify the object was created.</para>
    /// </summary>
    [Parameter(ParameterSetName = "OpenObject")]
    public SwitchParameter Creation { get; set; }

    /// <summary>
    /// <para type="description">Specify if access granted was granted.</para>
    /// </summary>
    [Parameter(ParameterSetName = "OpenObject")]
    [Parameter(ParameterSetName = "PrivilegeObject")]
    [Parameter(ParameterSetName = "PrivilegeService")]
    public SwitchParameter AccessGranted { get; set; }

    /// <summary>
    /// <para type="description">Specify the generate on close flag.</para>
    /// </summary>
    [Parameter(ParameterSetName = "CloseObject")]
    [Parameter(ParameterSetName = "DeleteObject")]
    public SwitchParameter GenerateOnClose { get; set; }

    /// <summary>
    /// <para type="description">Specify privileges.</para>
    /// </summary>
    [Parameter(ParameterSetName = "OpenObject")]
    [Parameter(Mandatory = true, ParameterSetName = "PrivilegeObject")]
    [Parameter(Mandatory = true, ParameterSetName = "PrivilegeService")]
    public TokenPrivilegeValue[] Privileges { get; set; }

    /// <summary>
    /// <para type="description">Specify to generate a delete audit event.</para>
    /// </summary>
    [Parameter(Mandatory = true, ParameterSetName = "DeleteObject")]
    public SwitchParameter Delete { get; set; }

    /// <summary>
    /// <para type="description">Specify to generate a close audit event.</para>
    /// </summary>
    [Parameter(Mandatory = true, ParameterSetName = "CloseObject")]
    public SwitchParameter Close { get; set; }

    /// <summary>
    /// <para type="description">Specify to generate a open audit event.</para>
    /// </summary>
    [Parameter(Mandatory = true, ParameterSetName = "OpenObject")]
    public SwitchParameter Open { get; set; }

    /// <summary>
    /// <para type="description">Specify to generate a privilege object audit event.</para>
    /// </summary>
    [Parameter(Mandatory = true, ParameterSetName = "PrivilegeObject")]
    public SwitchParameter PrivilegeObject { get; set; }

    /// <summary>
    /// <para type="description">Specify to generate a privilege service audit event.</para>
    /// </summary>
    [Parameter(Mandatory = true, ParameterSetName = "PrivilegeService")]
    public SwitchParameter PrivilegeService { get; set; }

    /// <summary>
    /// Process Record.
    /// </summary>
    protected override void ProcessRecord()
    {
        using var token = GetToken();
        if (Open)
        {
            if (string.IsNullOrEmpty(TypeName))
            {
                TypeName = SecurityDescriptor?.NtType.Name ?? throw new ArgumentException("Must specify a type name.");
            }
            WriteObject(NtSecurity.OpenObjectAudit(
                SubsystemName, HandleId, TypeName,
                Name, SecurityDescriptor, token,
                DesiredAccess, GrantedAccess, GetPrivileges(),
                Creation, AccessGranted));
        }
        else if (Close)
        {
            NtSecurity.CloseObjectAudit(SubsystemName,
                HandleId, GenerateOnClose);
        }
        else if (Delete)
        {
            NtSecurity.DeleteObjectAudit(SubsystemName,
                HandleId, GenerateOnClose);
        }
        else if (PrivilegeObject)
        {
            NtSecurity.PrivilegeObjectAudit(SubsystemName,
                HandleId, token, DesiredAccess,
                GetPrivileges(), AccessGranted);
        }
        else if (PrivilegeService)
        {
            NtSecurity.PrivilegedServiceAudit(SubsystemName,
                ServiceName, token, GetPrivileges(),
                AccessGranted);
        }
        else
        {
            throw new ArgumentException("Invalid audit type.");
        }
    }

    private IEnumerable<TokenPrivilege> GetPrivileges()
    {
        return Privileges?.Select(p => new TokenPrivilege(p, 0)) ?? new TokenPrivilege[0];
    }

    private NtToken GetToken()
    {
        if (Token != null)
        {
            return Token.DuplicateToken(TokenType.Impersonation,
                SecurityImpersonationLevel.Identification, TokenAccessRights.Query);
        }
        else
        {
            using NtToken token = NtToken.OpenEffectiveToken();
            return token.DuplicateToken(TokenType.Impersonation,
                SecurityImpersonationLevel.Identification, TokenAccessRights.Query);
        }
    }
}
