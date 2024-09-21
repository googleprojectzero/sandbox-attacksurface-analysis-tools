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

using NtCoreLib;
using NtCoreLib.Security.Authorization;
using NtCoreLib.Win32.DirectoryService;
using NtObjectManager.Provider;
using System;
using System.Management.Automation;
using System.Security.AccessControl;

namespace NtObjectManager.Cmdlets.Object;

/// <summary>
/// <para type="synopsis">Converts from a .NET ACL to a NT security descriptor.</para>
/// <para type="description">This cmdlet converts an existing .NET ACL (such as from Get-Acl) and creates a security descriptor object.</para>
/// </summary>
/// <example>
///   <code>Get-Acl $env:WinDir | ConvertTo-NtSecurityDescriptor</code>
///   <para>Converts the ACL for the windows directory to an NT security descriptor.</para>
/// </example>
[Cmdlet(VerbsData.ConvertTo, "NtSecurityDescriptor")]
[OutputType(typeof(SecurityDescriptor))]
public sealed class ConvertToNtSecurityDescriptorCmdlet : PSCmdlet
{
    private static Tuple<NtType, bool> GetTypeFromSecurity(ObjectSecurity object_security)
    {
        if (object_security is GenericObjectSecurity sd)
        {
            return Tuple.Create(sd.NtType, sd.IsDirectory);
        } 
        else if (object_security is FileSecurity)
        {
            return Tuple.Create(NtType.GetTypeByType<NtFile>(), false);
        }
        else if (object_security is DirectorySecurity)
        {
            return Tuple.Create(NtType.GetTypeByType<NtFile>(), true);
        }
        else if (object_security is DirectoryObjectSecurity)
        {
            return Tuple.Create(DirectoryServiceUtils.NtType, true);
        }
        else if (object_security is RegistrySecurity)
        {
            return Tuple.Create(NtType.GetTypeByType<NtKey>(), true);
        }
        else if (object_security is MutexSecurity)
        {
            return Tuple.Create(NtType.GetTypeByType<NtMutant>(), false);
        }
        else if (object_security is SemaphoreSecurity)
        {
            return Tuple.Create(NtType.GetTypeByType<NtSemaphore>(), false);
        }
        return Tuple.Create((NtType)null, false);
    }

    /// <summary>
    /// <para type="description">The .NET security descriptor.</para>
    /// </summary>
    [Parameter(Position = 0, Mandatory = true, ValueFromPipeline = true)]
    public ObjectSecurity InputObject { get; set; }

    /// <summary>
    /// Overridden ProcessRecord.
    /// </summary>
    protected override void ProcessRecord()
    {
        var sd = new SecurityDescriptor(InputObject.GetSecurityDescriptorBinaryForm());
        var type = GetTypeFromSecurity(InputObject);
        sd.NtType = type.Item1;
        sd.Container = type.Item2;
        WriteObject(sd, false);
    }
}
