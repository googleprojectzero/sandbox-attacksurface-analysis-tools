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
using NtCoreLib.Security.Authorization;
using NtCoreLib.Utilities.Collections;
using NtObjectManager.Utils;
using System;
using System.Management.Automation;

namespace NtObjectManager.Cmdlets.Object;

/// <summary>
/// <para type="synopsis">Create a new security descriptor which can be used on NT objects.</para>
/// <para type="description">This cmdlet creates a new instance of a SecurityDescriptor object. This can be 
/// used directly with one of the New-Nt* cmdlets (via the -SecurityDescriptor parameter) or by calling
/// SetSecurityDescriptor on an existing object (assume the object has been opened with the correct permissions.
/// </para>
/// </summary>
/// <example>
///   <code>$sd = New-NtSecurityDescriptor</code>
///   <para>Create a new empty security descriptor object.</para>
/// </example>
/// <example>
///   <code>$sd = New-NtSecurityDescriptor "O:BAG:BAD:(A;;GA;;;WD)"</code>
///   <para>Create a new security descriptor object from an SDDL string</para>
/// </example>
/// <example>
///   <code>$sd = New-NtSecurityDescriptor -NullDacl</code>
///   <para>Create a new security descriptor object with a NULL DACL.</para>
/// </example>
/// <example>
///   <code>$sd = New-NtSecurityDescriptor "D:(A;;GA;;;WD)"&#x0A;$obj = New-NtDirectory \BaseNamedObjects\ABC -SecurityDescriptor $sd</code>
///   <para>Create a new object directory with an explicit security descriptor.</para>
/// </example>
/// <example>
///   <code>$sd = New-NtSecurityDescriptor -Key $key -ValueName SD</code>
///   <para>Create a new security descriptor with the contents from the key $Key and value "SD".</para>
/// </example>
[Cmdlet(VerbsCommon.New, "NtSecurityDescriptor", DefaultParameterSetName = "NewSd")]
[OutputType(typeof(SecurityDescriptor))]
public sealed class NewNtSecurityDescriptorCmdlet : PSCmdlet
{
    /// <summary>
    /// <para type="description">Specify to create the security descriptor with a NULL DACL.</para>
    /// </summary>
    [Parameter(ParameterSetName = "NewSd")]
    public SwitchParameter NullDacl { get; set; }

    /// <summary>
    /// <para type="description">Specify to create the security descriptor with an empty DACL.</para>
    /// </summary>
    [Parameter(ParameterSetName = "NewSd")]
    public SwitchParameter EmptyDacl { get; set; }

    /// <summary>
    /// <para type="description">Specify to create the security descriptor with a NULL SACL.</para>
    /// </summary>
    [Parameter(ParameterSetName = "NewSd")]
    public SwitchParameter NullSacl { get; set; }

    /// <summary>
    /// <para type="description">Specify to create the security descriptor with an empty SACL.</para>
    /// </summary>
    [Parameter(ParameterSetName = "NewSd")]
    public SwitchParameter EmptySacl { get; set; }

    /// <summary>
    /// <para type="description">Specify thr owner for the new SD.</para>
    /// </summary>
    [Parameter(ParameterSetName = "NewSd")]
    public Sid Owner { get; set; }

    /// <summary>
    /// <para type="description">Specify the group for the new SD.</para>
    /// </summary>
    [Parameter(ParameterSetName = "NewSd")]
    public Sid Group { get; set; }

    /// <summary>
    /// <para type="description">Specify the DACL for the new SD. The ACL will be cloned.</para>
    /// </summary>
    [Parameter(ParameterSetName = "NewSd")]
    [AllowEmptyCollection]
    public Acl Dacl { get; set; }

    /// <summary>
    /// <para type="description">Specify the the SACL for the new SD. The ACL will be cloned.</para>
    /// </summary>
    [Parameter(ParameterSetName = "NewSd")]
    [AllowEmptyCollection]
    public Acl Sacl { get; set; }

    /// <summary>
    /// <para type="description">Specify to create the security descriptor from an SDDL representation.</para>
    /// </summary>
    [Parameter(Mandatory = true, Position = 0, ParameterSetName = "FromSddl")]
    public string Sddl { get; set; }

    /// <summary>
    /// <para type="description">Specify to create the security descriptor from an base64 string.</para>
    /// </summary>
    [Parameter(Mandatory = true, ParameterSetName = "FromBase64")]
    public string Base64 { get; set; }

    /// <summary>
    /// <para type="description">Specify to create the security descriptor from the default DACL of a token object.</para>
    /// </summary>
    [Parameter(Position = 0, ParameterSetName = "FromToken")]
    [AllowNull]
    public NtToken Token { get; set; }

    /// <summary>
    /// <para type="description">Specify mapping the generic accesses based on the NT Type.</para>
    /// </summary>
    [Parameter(ParameterSetName = "FromSddl"), 
     Parameter(ParameterSetName = "FromBytes"), 
     Parameter(ParameterSetName = "FromKey")]
    [Alias("MapType")]
    public SwitchParameter MapGeneric { get; set; }

    /// <summary>
    /// <para type="description">Specify a default NT type for the security descriptor.</para>
    /// </summary>
    [Parameter(ParameterSetName = "FromToken"),
        Parameter(ParameterSetName = "FromSddl"),
        Parameter(ParameterSetName = "FromBase64"),
        Parameter(ParameterSetName = "FromBytes"), 
        Parameter(ParameterSetName = "FromKey"),
        Parameter(ParameterSetName = "NewSd")]
    [ArgumentCompleter(typeof(NtTypeArgumentCompleter))]
    public NtType Type { get; set; }

    /// <summary>
    /// <para type="description">Specify the security descriptor is for a container.</para>
    /// </summary>
    [Parameter(ParameterSetName = "FromToken"),
        Parameter(ParameterSetName = "FromSddl"),
        Parameter(ParameterSetName = "FromBase64"),
        Parameter(ParameterSetName = "FromBytes"),
        Parameter(ParameterSetName = "FromKey"),
        Parameter(ParameterSetName = "NewSd")]
    public SwitchParameter Container { get; set; }

    /// <summary>
    /// <para type="description">Specify a byte array containing the security descriptor.</para>
    /// </summary>
    [Parameter(Mandatory = true, Position = 0, ParameterSetName = "FromBytes")]
    [Alias("Bytes")]
    public byte[] Byte { get; set; }

    /// <summary>
    /// <para type="description">Specify a registry key to read the security descriptor from.</para>
    /// </summary>
    [Parameter(Mandatory = true, Position = 0, ParameterSetName = "FromKey")]
    public NtKey Key { get; set; }

    /// <summary>
    /// <para type="description">Specify a registry value name in the key to read the security descriptor from.</para>
    /// </summary>
    [Parameter(Mandatory = true, Position = 1, ParameterSetName = "FromKey")]
    [AllowEmptyString]
    public string ValueName { get; set; }

    /// <summary>
    /// <para type="description">Specify a registry key value to read the security descriptor from.</para>
    /// </summary>
    [Parameter(Mandatory = true, Position = 0, ParameterSetName = "FromKeyValue")]
    public NtKeyValue KeyValue { get; set; }

    /// <summary>
    /// <para type="description">Specify additional control flags to apply to the SD. Not all the flags are accepted.</para>
    /// </summary>
    [Parameter(ParameterSetName = "FromSddl"),
     Parameter(ParameterSetName = "NewSd")]
    public SecurityDescriptorControl Control { get; set; }

    /// <summary>
    /// <para type="description">Specify optional object types for the new security descriptor.</para>
    /// </summary>
    [Parameter(ParameterSetName = "FromToken")]
    public Guid[] ObjectType { get; set; }

    /// <summary>
    /// <para type="description">Specify auto-inherit flags for new security descriptor.</para>
    /// </summary>
    [Parameter(ParameterSetName = "FromToken")]
    public SecurityAutoInheritFlags AutoInherit { get; set; }

    /// <summary>
    /// <para type="description">Specify parent for new security descriptor.</para>
    /// </summary>
    [Parameter(ParameterSetName = "FromToken")]
    public SecurityDescriptor Parent { get; set; }

    /// <summary>
    /// <para type="description">Specify creator for new security descriptor.</para>
    /// </summary>
    [Parameter(ParameterSetName = "FromToken")]
    public SecurityDescriptor Creator { get; set; }

    /// <summary>
    /// <para type="description">Specify to use the current Token for a new security descriptor.</para>
    /// </summary>
    [Parameter(ParameterSetName = "FromToken")]
    public SwitchParameter EffectiveToken { get; set; }

    /// <summary>
    /// Overridden ProcessRecord method.
    /// </summary>
    protected override void ProcessRecord()
    {
        if (MapGeneric && Type == null)
        {
            WriteWarning("Must specify Type for MapGeneric to work correctly.");
        }

        SecurityDescriptor sd;
        switch (ParameterSetName)
        {
            case "FromToken":
                {
                    Type = Type ?? Parent?.NtType ?? Creator?.NtType;
                    if (Type == null)
                    {
                        WriteWarning("Security descriptor type not specified, defaulting to File.");
                        Type = NtType.GetTypeByType<NtFile>();
                    }

                    using var list = new DisposableList();
                    if (EffectiveToken)
                    {
                        Token = list.AddResource(NtToken.OpenEffectiveToken());
                    }
                    sd = SecurityDescriptor.Create(Parent, Creator, ObjectType,
                        Container, AutoInherit, Token, Type.GenericMapping);
                }
                break;
            case "FromSddl":
                sd = new SecurityDescriptor(Sddl);
                break;
            case "FromBytes":
                sd = new SecurityDescriptor(Byte);
                break;
            case "FromKey":
                sd = new SecurityDescriptor(Key.QueryValue(ValueName).Data);
                break;
            case "FromKeyValue":
                sd = new SecurityDescriptor(KeyValue.Data);
                break;
            case "FromBase64":
                sd = SecurityDescriptor.ParseBase64(Base64);
                break;
            default:
                sd = CreateNewSecurityDescriptor();
                break;
        }

        sd.NtType = Type;
        sd.Container = Container;
        if (MapGeneric)
        {
            sd.MapGenericAccess();
        }

        sd.Control |= Control;
        WriteObject(sd);
    }

    private static Acl CreateAcl(bool empty_acl, bool null_acl)
    {
        if (!empty_acl && !null_acl)
        {
            return null;
        }
        return new Acl() { NullAcl = null_acl };
    }

    private SecurityDescriptor CreateNewSecurityDescriptor()
    {
        return new SecurityDescriptor
        {
            Dacl = Dacl?.Clone() ?? CreateAcl(EmptyDacl, NullDacl),
            Sacl = Sacl?.Clone() ?? CreateAcl(EmptySacl, NullSacl),
            Owner = Owner != null ? new SecurityDescriptorSid(Owner, false) : null,
            Group = Group != null ? new SecurityDescriptorSid(Group, false) : null
        };
    }
}
