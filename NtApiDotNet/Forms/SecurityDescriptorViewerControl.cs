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

using System.Windows.Forms;

namespace NtApiDotNet.Forms
{
    /// <summary>
    /// Control to display a security descriptor.
    /// </summary>
    public partial class SecurityDescriptorViewerControl : UserControl
    {
        private void AddAclTab(TabPage tab_page, AclViewerControl control, Acl acl, NtType type)
        {
            if (acl == null)
            {
                tabControl.TabPages.Remove(tab_page);
            }
            else
            {
                if (acl.NullAcl)
                {
                    tab_page.Controls.Remove(control);
                    tab_page.Controls.Add(new Label() { Text = "NULL ACL", Dock = DockStyle.Fill });
                }
                else
                {
                    control.SetAcl(acl, type);
                }
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
                label.Text = sid.Sid.Name;
            }
        }

        /// <summary>
        /// Set the security descriptor for the control.
        /// </summary>
        /// <param name="security_descriptor">Security descriptor to view.</param>
        /// <param name="type">NT type for view.</param>
        public void SetSecurityDescriptor(SecurityDescriptor security_descriptor, NtType type)
        {
            AddAclTab(tabPageDACL, aclViewerControlDacl, security_descriptor.Dacl, type);
            AddAclTab(tabPageSACL, aclViewerControlSacl, security_descriptor.Sacl, type);
            SetSidLabel(lblOwnerValue, security_descriptor.Owner);
            SetSidLabel(lblGroupValue, security_descriptor.Group);
            lblIntegrityValue.Text = security_descriptor.IntegrityLevel.ToString();
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
