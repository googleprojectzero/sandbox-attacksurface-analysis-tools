//  Copyright 2018 Google Inc. All Rights Reserved.
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

// NOTE: This file is a modified version of NdrParser.cs from OleViewDotNet
// https://github.com/tyranid/oleviewdotnet. It's been relicensed from GPLv3 by
// the original author James Forshaw to be used under the Apache License for this
// project.

using System;
using System.Windows.Forms;

namespace NtApiDotNet.Forms
{
    /// <summary>
    /// Control to display a security descriptor.
    /// </summary>
    public partial class SecurityDescriptorViewerControl : UserControl
    {
        private void AddAclTab(TabPage tab_page, AclViewerControl control, Acl acl, Type access_type, GenericMapping mapping, AccessMask valid_access, bool is_container)
        {
            if (acl == null)
            {
                tabControl.TabPages.Remove(tab_page);
            }
            else
            {
                control.SetAcl(acl, access_type, mapping, valid_access, is_container);
            }
        }

        private void SetSidLabel(Label label, SecurityDescriptorSid sid)
        {
            if (sid == null)
            {
                label.Text = "N/A";
            }
            else
            {
                if (sid.Defaulted)
                {
                    label.Text = $"{sid.Sid.Name} (Defaulted)";
                }
                label.Text = sid.Sid.Name;
            }
        }

        /// <summary>
        /// Set the security descriptor for the control.
        /// </summary>
        /// <param name="security_descriptor">Security descriptor to view.</param>
        /// <param name="type">NT type for view.</param>
        /// <param name="valid_access">The valid bit mask for access for this type.</param>
        /// <param name="is_container">True to indicate this object is a container.</param>
        public void SetSecurityDescriptor(SecurityDescriptor security_descriptor, NtType type, AccessMask valid_access, bool is_container)
        {
            SetSecurityDescriptor(security_descriptor, is_container ? type.ContainerAccessRightsType : type.AccessRightsType, 
                type.GenericMapping, valid_access, is_container);
        }

        /// <summary>
        /// Set the security descriptor for the control.
        /// </summary>
        /// <param name="security_descriptor">Security descriptor to view.</param>
        /// <param name="type">NT type for view.</param>
        /// <param name="valid_access">The valid bit mask for access for this type.</param>
        public void SetSecurityDescriptor(SecurityDescriptor security_descriptor, NtType type, AccessMask valid_access)
        {
            SetSecurityDescriptor(security_descriptor, type, valid_access, false);
        }

        /// <summary>
        /// Set the security descriptor for the control.
        /// </summary>
        /// <param name="security_descriptor">Security descriptor to view.</param>
        /// <param name="access_type">The enum type for the view.</param>
        /// <param name="mapping">Generic mapping for the type.</param>
        /// <param name="valid_access">The valid bit mask for access for this type.</param>
        /// <param name="is_container">True to indicate this object is a container.</param>
        public void SetSecurityDescriptor(SecurityDescriptor security_descriptor, Type access_type, GenericMapping mapping, AccessMask valid_access, bool is_container)
        {
            AddAclTab(tabPageDACL, aclViewerControlDacl, security_descriptor.Dacl, access_type, mapping, valid_access, is_container);
            AddAclTab(tabPageSACL, aclViewerControlSacl, security_descriptor.Sacl, access_type, mapping, valid_access, is_container);
            SetSidLabel(lblOwnerValue, security_descriptor.Owner);
            SetSidLabel(lblGroupValue, security_descriptor.Group);
            Ace label = security_descriptor.GetMandatoryLabel();
            if (label != null)
            {
                lblIntegrityValue.Text = $"{NtSecurity.GetIntegrityLevel(label.Sid)} ({label.Mask.ToMandatoryLabelPolicy()})";
            }
            else
            {
                lblIntegrityValue.Text = "N/A";
            }
        }

        /// <summary>
        /// Set the security descriptor for the control.
        /// </summary>
        /// <param name="security_descriptor">Security descriptor to view.</param>
        /// <param name="access_type">The enum type for the view.</param>
        /// <param name="mapping">Generic mapping for the type.</param>
        /// <param name="valid_access">The valid bit mask for access for this type.</param>
        public void SetSecurityDescriptor(SecurityDescriptor security_descriptor, Type access_type, GenericMapping mapping, AccessMask valid_access)
        {
            SetSecurityDescriptor(security_descriptor, access_type, mapping, valid_access, false);
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        public SecurityDescriptorViewerControl()
        {
            InitializeComponent();
        }
    }
}
