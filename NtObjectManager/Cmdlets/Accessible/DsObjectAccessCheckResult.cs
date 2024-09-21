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

using NtCoreLib.Security.Authorization;
using NtCoreLib.Win32.DirectoryService;
using System.Collections.Generic;
using System.Linq;

namespace NtObjectManager.Cmdlets.Accessible;

/// <summary>
/// <para type="description">Access check result for a directory service object.</para>
/// </summary>
public sealed class DsObjectAccessCheckResult
{
    /// <summary>
    /// The name of the object which was accessed.
    /// </summary>
    public string DistinguishedName { get; }

    /// <summary>
    /// The name of the object.
    /// </summary>
    public string Name { get; }

    /// <summary>
    /// The domain of the object.
    /// </summary>
    public string Domain { get; }

    /// <summary>
    /// Granted access for the SD with the base object type.
    /// </summary>
    public DirectoryServiceAccessRights GrantedAccess { get; }

    /// <summary>
    /// Granted access for the SD without any object type.
    /// </summary>
    public DirectoryServiceAccessRights GrantedAccessNoType { get; }

    /// <summary>
    /// The maximum granted access for any components of the object.
    /// </summary>
    public DirectoryServiceAccessRights MaximumGrantedAccess { get; }

    /// <summary>
    /// Is the entry modifiable by the user in any way?
    /// </summary>
    public bool Modifiable => (MaximumGrantedAccess & (DirectoryServiceAccessRights.WriteDac |
        DirectoryServiceAccessRights.WriteOwner | DirectoryServiceAccessRights.WriteProp | 
        DirectoryServiceAccessRights.Self | DirectoryServiceAccessRights.CreateChild | DirectoryServiceAccessRights.DeleteChild
        | DirectoryServiceAccessRights.Delete | DirectoryServiceAccessRights.DeleteTree)) != 0;

    /// <summary>
    /// Is the entry controllable by one or more control access rights?
    /// </summary>
    public bool Controllable => AnyGrantedControl;

    /// <summary>
    /// The schema class for the object.
    /// </summary>
    public DirectoryServiceSchemaClass SchemaClass { get; }

    /// <summary>
    /// List of dynamic auxiliary classes.
    /// </summary>
    public IReadOnlyList<DirectoryServiceSchemaClass> DynamicAuxiliaryClasses { get; }

    /// <summary>
    /// The name of the schema class.
    /// </summary>
    public string ObjectClass => SchemaClass.Name;

    /// <summary>
    /// Access check results for extended rights.
    /// </summary>
    public IEnumerable<DsObjectTypeAccessCheckResult<DirectoryServiceExtendedRight>> ExtendedRights => PropertySets.Concat(Control).Concat(WriteValidated);

    /// <summary>
    /// Access check results for schema classes.
    /// </summary>
    public IReadOnlyList<DsObjectTypeAccessCheckResult<DirectoryServiceSchemaClass>> Classes { get; }

    /// <summary>
    /// Get the list of creatable classes.
    /// </summary>
    public IEnumerable<DirectoryServiceSchemaClass> CreateableClasses
        => Classes.Where(a => a.IsAccessGranted(DirectoryServiceAccessRights.CreateChild)).Select(a => a.Object);

    /// <summary>
    /// Check if there are any createable classes.
    /// </summary>
    public bool AnyCreateableClasses => CreateableClasses.Any();

    /// <summary>
    /// Get the list of deletable classes.
    /// </summary>
    public IEnumerable<DirectoryServiceSchemaClass> DeletableClasses
        => Classes.Where(a => a.IsAccessGranted(DirectoryServiceAccessRights.DeleteChild)).Select(a => a.Object);

    /// <summary>
    /// Check if there are any deletable classes.
    /// </summary>
    public bool AnyDeletableClasses => DeletableClasses.Any();

    /// <summary>
    /// Access check results for schema attributes.
    /// </summary>
    public IReadOnlyList<DsObjectTypeAccessCheckResult<DirectoryServiceSchemaAttribute>> Attributes { get; }

    /// <summary>
    /// Get the list of readable attributes.
    /// </summary>
    public IEnumerable<DirectoryServiceSchemaAttribute> ReadableAttributes
        => Attributes.Where(a => a.IsAccessGranted(DirectoryServiceAccessRights.ReadProp)).Select(a => a.Object);

    /// <summary>
    /// Get the list of writable attributes.
    /// </summary>
    public IEnumerable<DirectoryServiceSchemaAttribute> WritableAttributes 
        => Attributes.Where(a => a.IsAccessGranted(DirectoryServiceAccessRights.WriteProp)).Select(a => a.Object);

    /// <summary>
    /// Check if there are any writable attributes.
    /// </summary>
    public bool AnyWritableAttributes => WritableAttributes.Any();

    /// <summary>
    /// Property set extended rights.
    /// </summary>
    public IReadOnlyList<DsObjectTypeAccessCheckResult<DirectoryServiceExtendedRight>> PropertySets { get; }

    /// <summary>
    /// Get the list of readable property sets.
    /// </summary>
    public IEnumerable<DirectoryServiceExtendedRight> ReadablePropertySets
        => PropertySets.Where(a => a.IsAccessGranted(DirectoryServiceAccessRights.ReadProp)).Select(a => a.Object);

    /// <summary>
    /// Get the list of writable attributes.
    /// </summary>
    public IEnumerable<DirectoryServiceExtendedRight> WritablePropertySets
        => PropertySets.Where(a => a.IsAccessGranted(DirectoryServiceAccessRights.WriteProp)).Select(a => a.Object);

    /// <summary>
    /// Control access rights.
    /// </summary>
    public IReadOnlyList<DsObjectTypeAccessCheckResult<DirectoryServiceExtendedRight>> Control { get; }

    /// <summary>
    /// Get the list of control access rights granted.
    /// </summary>
    public IEnumerable<DirectoryServiceExtendedRight> GrantedControl
        => Control.Where(a => a.IsAccessGranted(DirectoryServiceAccessRights.ControlAccess)).Select(a => a.Object);

    /// <summary>
    /// Check if there are any granted control access rights.
    /// </summary>
    public bool AnyGrantedControl => GrantedControl.Any();

    /// <summary>
    /// Write validated access rights.
    /// </summary>
    public IReadOnlyList<DsObjectTypeAccessCheckResult<DirectoryServiceExtendedRight>> WriteValidated { get; }

    /// <summary>
    /// Get the list of write validated access rights granted.
    /// </summary>
    public IEnumerable<DirectoryServiceExtendedRight> GrantedWriteValidated
        => WriteValidated.Where(a => a.IsAccessGranted(DirectoryServiceAccessRights.Self)).Select(a => a.Object);

    /// <summary>
    /// Check if there are any granted write validated access rights.
    /// </summary>
    public bool AnyGrantedWriteValidated => GrantedWriteValidated.Any();

    /// <summary>
    /// The security descriptor associated with this access check.
    /// </summary>
    public SecurityDescriptor SecurityDescriptor { get; }

    /// <summary>
    /// The SID owner of the resource from the security descriptor.
    /// </summary>
    public string Owner => SecurityDescriptor.Owner.Sid.Name;

    /// <summary>
    /// Information the token used in the access check.
    /// </summary>
    public TokenInformation TokenInfo { get; }

    /// <summary>
    /// The username for the token.
    /// </summary>
    public string UserName => TokenInfo.UserName;

    /// <summary>
    /// Was read access granted?
    /// </summary>
    public bool IsRead { get; }

    /// <summary>
    /// Was write access granted?
    /// </summary>
    public bool IsWrite { get; }

    /// <summary>
    /// Was execute access granted?
    /// </summary>
    public bool IsExecute { get; }

    /// <summary>
    /// Was all access granted?
    /// </summary>
    public bool IsAll { get; }

    /// <summary>
    /// Is the object deleted?
    /// </summary>
    public bool Deleted { get; }

    internal DsObjectAccessCheckResult(string dn, string name, DirectoryServiceSchemaClass schema_class,
        bool is_deleted, string domain, AccessMask granted_access,
        AccessMask granted_access_no_type, AccessMask maximum_granted_access,
        IEnumerable<DsObjectTypeAccessCheckResult<DirectoryServiceExtendedRight>> property_sets,
        IEnumerable<DsObjectTypeAccessCheckResult<DirectoryServiceExtendedRight>> control,
        IEnumerable<DsObjectTypeAccessCheckResult<DirectoryServiceExtendedRight>> write_validated,
        IEnumerable<DsObjectTypeAccessCheckResult<DirectoryServiceSchemaClass>> schema_classes,
        IEnumerable<DsObjectTypeAccessCheckResult<DirectoryServiceSchemaAttribute>> schema_attributes,
        IEnumerable<DsObjectInformation> dynamic_aux_classes,
        SecurityDescriptor sd, TokenInformation token_info)
    {
        DistinguishedName = dn;
        Name = name;
        SchemaClass = schema_class;
        Domain = domain;
        GrantedAccess = granted_access.ToSpecificAccess<DirectoryServiceAccessRights>();
        GrantedAccessNoType = granted_access_no_type.ToSpecificAccess<DirectoryServiceAccessRights>();
        MaximumGrantedAccess = maximum_granted_access.ToSpecificAccess<DirectoryServiceAccessRights>();
        PropertySets = property_sets.ToList().AsReadOnly();
        Control = control.ToList().AsReadOnly();
        WriteValidated = write_validated.ToList().AsReadOnly();
        Classes = schema_classes.ToList().AsReadOnly();
        Attributes = schema_attributes.ToList().AsReadOnly();
        TokenInfo = token_info;
        SecurityDescriptor = sd;
        Deleted = is_deleted;
        DynamicAuxiliaryClasses = dynamic_aux_classes.Select(c => c.SchemaClass).ToList().AsReadOnly();

        var mapping = DirectoryServiceUtils.GenericMapping;
        IsRead = mapping.HasRead(MaximumGrantedAccess);
        IsWrite = mapping.HasWrite(MaximumGrantedAccess);
        IsExecute = mapping.HasExecute(MaximumGrantedAccess);
        IsAll = mapping.HasAll(MaximumGrantedAccess);
    }
}
