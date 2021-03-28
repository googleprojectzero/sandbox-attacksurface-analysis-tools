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

using NtApiDotNet;
using NtApiDotNet.Security;
using NtApiDotNet.Utilities.Security;
using NtObjectManager.Utils;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Management.Automation;

namespace NtObjectManager.Cmdlets.Object
{
    /// <summary>
    /// <para type="synopsis">Gets the granted access to a security descriptor or object.</para>
    /// <para type="description">This cmdlet allows you to determine the granted access to a particular
    /// resource through a security descriptor or a reference to an object.</para>
    /// </summary>
    /// <example>
    ///   <code>Get-NtGrantedAccess $sd -Type $(Get-NtType File)</code>
    ///   <para>Get the maximum access for a security descriptor for a file object.</para>
    /// </example>
    /// <example>
    ///   <code>Get-NtGrantedAccess -Sddl "O:BAG:BAD:(A;;GA;;;WD)" -Type $(Get-NtType Process)</code>
    ///   <para>Get the maximum access for a security descriptor for a process object based on an SDDL string.</para>
    /// </example>
    /// <example>
    ///   <code>Get-NtGrantedAccess -Object $obj</code>
    ///   <para>Get the maximum access for a security descriptor for an object.</para>
    /// </example>
    [Cmdlet(VerbsCommon.Get, "NtGrantedAccess", DefaultParameterSetName = "sd")]
    public class GetNtGrantedAccessCmdlet : PSCmdlet, IDynamicParameters
    {
        private RuntimeDefinedParameterDictionary _dict;

        /// <summary>
        /// <para type="description">Specify a security descriptor.</para>
        /// </summary>
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = "sd")]
        [SecurityDescriptorTransform]
        public SecurityDescriptor SecurityDescriptor { get; set; }

        /// <summary>
        /// <para type="description">Specify a security descriptor in SDDL format.</para>
        /// </summary>
        [Parameter(Mandatory = true, ParameterSetName = "sddl")]
        public string Sddl { get; set; }

        /// <summary>
        /// <para type="description">Specify the NT type for the access check.</para>
        /// </summary>
        [Parameter(ParameterSetName = "sd"), 
            Parameter(Mandatory = true, ParameterSetName = "sddl"), 
            ArgumentCompleter(typeof(NtTypeArgumentCompleter))]
        public NtType Type { get; set; }

        /// <summary>
        /// <para type="description">Specify an access mask to check against. Overrides GenericAccess.</para>
        /// </summary>
        [Parameter]
        public AccessMask? RawAccess { get; set; }

        /// <summary>
        /// <para type="description">Specify an object to get security descriptor from.</para>
        /// </summary>
        [Parameter(Mandatory = true, ParameterSetName = "obj")]
        public INtObjectSecurity Object { get; set; }

        /// <summary>
        /// <para type="description">Specify a token object to do the access check against. If not specified then current effective token is used.</para>
        /// </summary>
        [Parameter]
        public NtToken Token { get; set; }

        /// <summary>
        /// <para type="description">Specify whether to map the access mask back to generic rights.</para>
        /// </summary>
        [Parameter]
        public SwitchParameter MapToGeneric { get; set; }

        /// <summary>
        /// <para type="description">Specify whether to return a string rather than an enumeration value.</para>
        /// </summary>
        [Parameter]
        [Alias("ConvertToString")]
        public SwitchParameter AsString { get; set; }

        /// <summary>
        /// <para type="description">Specify whether to return a string using SDK style names.</para>
        /// </summary>
        [Parameter]
        public SwitchParameter AsSDKString { get; set; }

        /// <summary>
        /// <para type="description">Specify a principal SID to user when checking security descriptors with SELF SID.</para>
        /// </summary>
        [Parameter]
        public Sid Principal { get; set; }

        /// <summary>
        /// <para type="description">Specify to return the access check result rather than get the granted access.</para>
        /// </summary>
        [Parameter]
        public SwitchParameter PassResult { get; set; }

        /// <summary>
        /// <para type="description">Specify to return the access check results as a list. Can only be used with Object Types.</para>
        /// </summary>
        [Parameter]
        public SwitchParameter ResultList { get; set; }

        /// <summary>
        /// <para type="description">Specify object types for access check.</para>
        /// </summary>
        [Parameter]
        public ObjectTypeTree ObjectType { get; set; }

        /// <summary>
        /// <para type="description">Specify to enable auditing for this access check.</para>
        /// </summary>
        [Parameter]
        public SwitchParameter Audit { get; set; }

        private AccessMask GetDesiredAccess()
        {
            NtType type = GetNtType();
            if (RawAccess.HasValue)
            {
                return type.MapGenericRights(RawAccess.Value);
            }

            if (!_dict.GetValue("Access", out Enum access))
            {
                return GenericAccessRights.MaximumAllowed;
            }

            return type.MapGenericRights(access);
        }

        private SecurityDescriptor GetSecurityDescriptor()
        {
            if (SecurityDescriptor != null)
            {
                return SecurityDescriptor;
            }
            else if (Sddl != null)
            {
                return new SecurityDescriptor(Sddl);
            }
            else
            {
                return Object?.GetSecurityDescriptor(SecurityInformation.AllNoSacl);
            }
        }

        private NtType GetNtType()
        {
            NtType type;
            if (Type != null)
            {
                type = Type;
            }
            else
            {
                type = GetSecurityDescriptor()?.NtType;
            }
            
            return type;
        }

        private NtToken GetToken()
        {
            TokenAccessRights access_rights = Audit ? TokenAccessRights.Impersonate : 0;
            if (Token != null)
            {
                return Token.DuplicateToken(TokenType.Impersonation, 
                    SecurityImpersonationLevel.Identification, access_rights | TokenAccessRights.Query);
            }
            else
            {
                using (NtToken token = NtToken.OpenEffectiveToken())
                {
                    return token.DuplicateToken(TokenType.Impersonation, 
                        SecurityImpersonationLevel.Identification, access_rights | TokenAccessRights.Query);
                }
            }
        }

        /// <summary>
        /// Overridden process record method.
        /// </summary>
        protected override void ProcessRecord()
        {
            using (NtToken token = GetToken())
            {
                NtType type = GetNtType();
                if (type == null)
                    throw new ArgumentException("Must specify a Type.");
                var object_types = ObjectType?.ToArray();
                IEnumerable<AccessCheckResultGeneric> results;
                if (Audit)
                {
                    results = RunAuditCheck(token, type, object_types).Select(r => r.ToSpecificAccess(type.AccessRightsType));
                }
                else
                {
                    results = RunCheck(token, type, object_types).Select(r => r.ToSpecificAccess(type.AccessRightsType));
                }

                if (PassResult)
                {
                    WriteObject(results, true);
                    return;
                }

                var masks = results.Select(r =>  MapToGeneric ? r.SpecificGenericGrantedAccess : r.SpecificGrantedAccess);
                if (AsString || AsSDKString)
                {
                    WriteObject(masks.Select(m => NtSecurity.AccessMaskToString(m, type.AccessRightsType, 
                        type.GenericMapping, false, AsSDKString)), true);
                }
                else
                {
                    WriteObject(masks, true);
                }
            }
        }

        private IEnumerable<AccessCheckResult> RunAuditCheck(NtToken token, NtType type, ObjectTypeEntry[] object_types)
        {
            _dict.GetValue("SubsystemName", out string subsystem_name);
            _dict.GetValue("HandleId", out IntPtr? handle_id);
            _dict.GetValue("ObjectTypeName", out string object_type_name);
            _dict.GetValue("ObjectName", out string object_name);
            _dict.GetValue("ObjectCreation", out SwitchParameter? object_creation);
            _dict.GetValue("AuditType", out AuditEventType? event_type);
            _dict.GetValue("AuditFlags", out AuditAccessCheckFlags? flags);

            var results = new List<AccessCheckResult>();
            if (ResultList)
            {
                results.AddRange(NtSecurity.AccessCheckWithResultListAudit(
                    subsystem_name, handle_id ?? IntPtr.Zero, object_type_name, 
                    object_name, object_creation ?? new SwitchParameter(),
                    event_type ?? AuditEventType.AuditEventObjectAccess,
                    flags ?? AuditAccessCheckFlags.None,
                    GetSecurityDescriptor(),
                    token, GetDesiredAccess(), Principal, type.GenericMapping, object_types));
            }
            else
            {
                results.Add(NtSecurity.AccessCheckAudit(
                    subsystem_name, handle_id ?? IntPtr.Zero, object_type_name,
                    object_name, object_creation ?? new SwitchParameter(),
                    event_type ?? AuditEventType.AuditEventObjectAccess,
                    flags ?? AuditAccessCheckFlags.None,
                    GetSecurityDescriptor(), token, GetDesiredAccess(), 
                    Principal, type.GenericMapping, object_types));
            }
            return results;
        }

        private IEnumerable<AccessCheckResult> RunCheck(NtToken token, NtType type, ObjectTypeEntry[] object_types)
        {
            var results = new List<AccessCheckResult>();
            if (ResultList)
            {
                results.AddRange(NtSecurity.AccessCheckWithResultList(GetSecurityDescriptor(),
                    token, GetDesiredAccess(), Principal, type.GenericMapping, object_types));
            }
            else
            {
                results.Add(NtSecurity.AccessCheck(GetSecurityDescriptor(),
                    token, GetDesiredAccess(), Principal, type.GenericMapping, object_types));
            }
            return results;
        }

        object IDynamicParameters.GetDynamicParameters()
        {
            _dict = new RuntimeDefinedParameterDictionary();
            Type access_type = GetNtType()?.AccessRightsType ?? typeof(GenericAccessRights);
            _dict.AddDynamicParameter("Access", access_type, false);

            if (Audit)
            {
                _dict.AddDynamicParameter("SubsystemName", typeof(string), true);
                _dict.AddDynamicParameter("HandleId", typeof(IntPtr), false);
                _dict.AddDynamicParameter("ObjectTypeName", typeof(string), true);
                _dict.AddDynamicParameter("ObjectName", typeof(string), true);
                _dict.AddDynamicParameter("ObjectCreation", typeof(SwitchParameter), false);
                _dict.AddDynamicParameter("AuditType", typeof(AuditEventType), false);
                _dict.AddDynamicParameter("AuditFlags", typeof(AuditAccessCheckFlags), false);
            }

            return _dict;
        }
    }
}
