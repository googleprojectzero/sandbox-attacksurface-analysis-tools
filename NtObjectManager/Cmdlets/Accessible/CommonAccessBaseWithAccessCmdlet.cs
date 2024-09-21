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
using System;
using System.Management.Automation;

namespace NtObjectManager.Cmdlets.Accessible;

/// <summary>
/// Base class for accessible checks with an access parameter.
/// </summary>
/// <typeparam name="A">The type of access rights to check against.</typeparam>
public abstract class CommonAccessBaseWithAccessCmdlet<A> : CommonAccessBaseCmdlet where A : Enum
{
    /// <summary>
    /// <para type="description">Access rights to check for in an object's access.</para>
    /// </summary>
    [Parameter]
    [Alias("AccessRights")]
    public A Access { get; set; }

    /// <summary>
    /// <para type="description">If AccessRights specified require that only part of the access rights
    /// are required to match an access check.</para>
    /// </summary>
    [Parameter]
    public SwitchParameter AllowPartialAccess { get; set; }

    /// <summary>
    /// <para type="description">If set an access entry will be generated even if granted access is 0.</para>
    /// </summary>
    [Parameter]
    public SwitchParameter AllowEmptyAccess { get; set; }

    private protected bool IsAccessGranted(AccessMask granted_access, AccessMask access_rights)
    {
        if (granted_access.IsEmpty)
        {
            return AllowEmptyAccess;
        }

        if (access_rights.IsEmpty)
        {
            return true;
        }

        if (AllowPartialAccess)
        {
            return granted_access.IsAccessGranted(access_rights);
        }

        return granted_access.IsAllAccessGranted(access_rights);
    }

    private protected SecurityInformation GetMaximumSecurityInformation(A granted_access)
    {
        SecurityInformation sec_info = SecurityInformation.AllBasic;
        AccessMask mask = granted_access;
        if (mask.IsAccessGranted(GenericAccessRights.ReadControl))
        {
            sec_info = SecurityInformation.AllNoSacl;
        }
        if (mask.IsAccessGranted(GenericAccessRights.AccessSystemSecurity))
        {
            sec_info |= SecurityInformation.Sacl;
        }
        return sec_info;
    }

    private protected SecurityInformation GetMaximumSecurityInformation(NtObject obj)
    {
        return GetMaximumSecurityInformation(obj.GrantedAccessMask.ToSpecificAccess<A>());
    }

    private protected NtResult<SecurityDescriptor> GetSecurityDescriptor(NtObject obj)
    {
        SecurityInformation sec_info = GetMaximumSecurityInformation(obj);
        return obj.GetSecurityDescriptor(sec_info, false);
    }

    private protected NtResult<SecurityDescriptor> GetSecurityDescriptorReOpen<O, X>(NtObjectWithDuplicate<O, X> obj) where O : NtObject where X : Enum
    {
        AccessMask desired_access = GenericAccessRights.ReadControl;
        if (HasSecurityPrivilege())
        {
            desired_access |= GenericAccessRights.AccessSystemSecurity;
        }

        using (var o = obj.ReOpen(desired_access.ToSpecificAccess<X>(), false))
        {
            if (o.IsSuccess)
                return GetSecurityDescriptor(o.Result);
        }
        return GetSecurityDescriptor(obj);
    }

    private protected A GetMaximumAccess(A access)
    {
        if (!HasSecurityPrivilege())
        {
            return access;
        }

        AccessMask mask = access;
        mask |= GenericAccessRights.AccessSystemSecurity;
        return mask.ToSpecificAccess<A>();
    }

    private protected T GetMaximumAccessGeneric<T>(T access) where T : Enum
    {
        if (!HasSecurityPrivilege())
        {
            return access;
        }

        AccessMask mask = access;
        mask |= GenericAccessRights.AccessSystemSecurity;
        return mask.ToSpecificAccess<T>();
    }
}