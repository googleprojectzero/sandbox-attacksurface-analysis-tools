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
using NtObjectManager.Utils;
using System;
using System.Collections.Generic;
using System.Management.Automation;

namespace NtObjectManager.Cmdlets.Object
{
    /// <summary>
    /// ACL type for ACE removal.
    /// </summary>
    [Flags]
    public enum RemoveAclType
    {
        /// <summary>
        /// Only remove from the DACL.
        /// </summary>
        Dacl = 1,
        /// <summary>
        /// Only remove from the SACL.
        /// </summary>
        Sacl = 2,
        /// <summary>
        /// Remove from both ACL and SACL.
        /// </summary>
        Both = Dacl | Sacl,
    }

    /// <summary>
    /// <para type="synopsis">Adds an ACE to a security descriptor.</para>
    /// <para type="description">This cmdlet adds an ACE to the specified security descriptor. It will
    /// automatically select the DACL or SACL depending on the ACE type requested. It also supports
    /// specifying a Condition for callback ACEs and Object GUIDs for Object ACEs. The Access property
    /// changes behavior depending on the NtType property of the Security Descriptor.
    /// </para>
    /// </summary>
    /// <example>
    ///   <code>Remove-NtSecurityDescriptorAce $sd -Sid "WD"</code>
    ///   <para>Remove all ACEs from DACL and SACL with the World SID.</para>
    /// </example>
    /// <example>
    ///   <code>Remove-NtSecurityDescriptorAce $sd -Type Denied</code>
    ///   <para>Remove all Denied ACEs from DACL.</para>
    /// </example>
    /// <example>
    ///   <code>Remove-NtSecurityDescriptorAce $sd -Flags Inherited -AclType Dacl</code>
    ///   <para>Remove all inherited ACEs from the DACL only.</para>
    /// </example>
    /// <example>
    ///   <code>Remove-NtSecurityDescriptorAce $sd -Flags ObjectInherit,ContainerInherit -AllFlags</code>
    ///   <para>Remove all ACEs with Flags set to ObjectInherit and ContainerInherit from the DACL and SACL.</para>
    /// </example>
    /// <example>
    ///   <code>Remove-NtSecurityDescriptorAce $sd -Access 0x20019</code>
    ///   <para>Remove all ACEs with the Access Mask set to 0x20019 from the DACL and SACL.</para>
    /// </example>
    /// <example>
    ///   <code>Remove-NtSecurityDescriptorAce $sd -Filter { $_.IsConditionalAce }</code>
    ///   <para>Remove all condition ACEs from the DACL and SACL.</para>
    /// </example>
    /// <example>
    ///   <code>Remove-NtSecurityDescriptorAce $sd -Ace @($a1, $a2)</code>
    ///   <para>Remove all ACEs which match a list from the DACL and SACL.</para>
    /// </example>
    /// <example>
    ///   <code>@($a1, $a2) | Remove-NtSecurityDescriptorAce $sd</code>
    ///   <para>Remove all ACEs which match a list from the DACL and SACL.</para>
    /// </example>
    /// <example>
    ///   <code>Remove-NtSecurityDescriptorAce $sd -Sid "WD" -WhatIf</code>
    ///   <para>Test what ACEs would be removed from DACL and SACL with the World SID.</para>
    /// </example>
    /// <example>
    ///   <code>Remove-NtSecurityDescriptorAce $sd -Sid "WD" -Confirm</code>
    ///   <para>Remove all ACEs from DACL and SACL with the World SID with confirmation.</para>
    /// </example>
    [Cmdlet(VerbsCommon.Remove, "NtSecurityDescriptorAce", DefaultParameterSetName = "FromSid", SupportsShouldProcess = true)]
    [OutputType(typeof(Ace))]
    public sealed class RemoveNtSecurityDescriptorAceCmdlet : PSCmdlet
    {
        #region Constructors
        /// <summary>
        /// Constuctor.
        /// </summary>
        public RemoveNtSecurityDescriptorAceCmdlet()
        {
            AclType = RemoveAclType.Both;
        }
        #endregion

        #region Public Properties
        /// <summary>
        /// <para type="description">Specify to create the security descriptor with a NULL DACL.</para>
        /// </summary>
        [Parameter(Position = 0, Mandatory = true)]
        [SecurityDescriptorTransform]
        public SecurityDescriptor SecurityDescriptor { get; set; }

        /// <summary>
        /// <para type="description">Specify to add ACE with SID.</para>
        /// </summary>
        [Parameter(Position = 1, ParameterSetName = "FromSid")]
        public Sid Sid { get; set; }

        /// <summary>
        /// <para type="description">Specify the type of ACE.</para>
        /// </summary>
        [Parameter(ParameterSetName = "FromSid")]
        public AceType? Type { get; set; }

        /// <summary>
        /// <para type="description">Specify the ACE flags.</para>
        /// </summary>
        [Parameter(ParameterSetName = "FromSid")]
        public AceFlags? Flags { get; set; }

        /// <summary>
        /// <para type="description">Specify the ACE flags must all match. The default is to select on a partial match.</para>
        /// </summary>
        [Parameter(ParameterSetName = "FromSid")]
        public SwitchParameter AllFlags { get; set; }

        /// <summary>
        /// <para type="description">Specify the access.</para>
        /// </summary>
        [Parameter(ParameterSetName = "FromSid")]
        public AccessMask? Access { get; set; }

        /// <summary>
        /// <para type="description">Specify a filter to select what to remove.</para>
        /// </summary>
        [Parameter(ParameterSetName = "FromFilter", Position = 1)]
        public ScriptBlock Filter { get; set; }

        /// <summary>
        /// <para type="description">Specify what ACLs to remove the ACEs from.</para>
        /// </summary>
        public RemoveAclType AclType { get; set; }

        /// <summary>
        /// <para type="description">Specify list of ACEs to remove.</para>
        /// </summary>
        [Parameter(ParameterSetName = "FromAce", Position = 1, ValueFromPipeline = true)]
        public Ace[] Ace { get; set; }

        /// <summary>
        /// <para type="description">Return the ACEs removed by the operation.</para>
        /// </summary>
        [Parameter]
        public SwitchParameter PassThru { get; set; }

        #endregion

        #region Protected Members
        /// <summary>
        /// Process Record.
        /// </summary>
        protected override void ProcessRecord()
        {
            IEnumerable<Ace> aces = new Ace[0];
            switch (ParameterSetName)
            {
                case "FromSid":
                    aces = FilterFromSid();
                    break;
                case "FromFilter":
                    aces = FilterFromFilter();
                    break;
                case "FromAce":
                    aces = FilterFromAce();
                    break;
            }

            if (PassThru)
            {
                WriteObject(aces, true);
            }
        }
        #endregion

        #region Private Members
        private bool ProcessAce(List<Ace> removed, Ace ace, bool dacl, Func<Ace, bool> filter)
        {
            if (!filter(ace))
            {
                return false;
            }

            if (!ShouldProcess($"Type:{ace.Type} Sid:{ace.Sid} Mask:{ace.Mask:X08} in {(dacl ? "DACL" : "SACL")}"))
            {
                return false;
            }

            removed.Add(ace);

            return true;
        }

        private static bool HasAcl(Acl acl)
        {
            return acl != null && !acl.NullAcl;
        }

        private void FilterWithFilter(List<Ace> removed, Acl acl, bool dacl, Func<Ace, bool> filter)
        {
            if (!HasAcl(acl))
            {
                return;
            }

            acl.RemoveAll(a => ProcessAce(removed, a, dacl, filter));
        }

        private IEnumerable<Ace> FilterWithFilter(Func<Ace, bool> filter)
        {
            List<Ace> removed = new List<Ace>();
            if (AclType.HasFlag(RemoveAclType.Dacl))
            {
                FilterWithFilter(removed, SecurityDescriptor.Dacl, true, filter);
            }
            if (AclType.HasFlag(RemoveAclType.Sacl))
            {
                FilterWithFilter(removed, SecurityDescriptor.Sacl, false, filter);
            }
            return removed;
        }

        private IEnumerable<Ace> FilterFromFilter()
        {
            return FilterWithFilter(a => Filter.InvokeWithArg(false, a));
        }

        private bool CheckSid(Ace ace)
        {
            if (Sid != null && ace.Sid != Sid)
            {
                return false;
            }
            if (Type.HasValue && ace.Type != Type)
            {
                return false;
            }
            if (Access.HasValue && ace.Mask != Access)
            {
                return false;
            }
            if (Flags.HasValue)
            {
                if (AllFlags)
                {
                    if (ace.Flags != Flags)
                    {
                        return false;
                    }
                }
                else
                {
                    if ((ace.Flags & Flags) != Flags)
                    {
                        return false;
                    }
                }

            }
            return true;
        }

        private IEnumerable<Ace> FilterFromSid()
        {
            if (Sid == null && !Type.HasValue && !Access.HasValue && !Flags.HasValue)
            {
                WriteWarning("No filter parameters specified. Not removing any ACEs.");
                return new Ace[0];
            }

            return FilterWithFilter(CheckSid);
        }

        private IEnumerable<Ace> FilterFromAce()
        {
            HashSet<Ace> aces = new HashSet<Ace>(Ace);
            return FilterWithFilter(a => aces.Contains(a));
        }

        #endregion
    }
}
