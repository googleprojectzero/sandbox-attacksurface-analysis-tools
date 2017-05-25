//  Copyright 2015 Google Inc. All Rights Reserved.
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

using SandboxAnalysisUtils;
using NtApiDotNet;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Drawing;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Management;
using System.Windows.Forms;

namespace TokenViewer
{
    public partial class TokenForm : Form
    {
        private NtToken _token;

        static string FormatLuid(Luid luid)
        {
            return String.Format("{0:X08}-{1:X08}",
                luid.HighPart, luid.LowPart);
        }

        private static void PopulateGroupList(ListView listView, IEnumerable<UserGroup> groups)
        {
            foreach (UserGroup group in groups)
            {
                GroupAttributes flags = group.Attributes & ~(GroupAttributes.EnabledByDefault);

                if ((flags & GroupAttributes.Integrity) == GroupAttributes.None)
                {
                    ListViewItem item = new ListViewItem(group.ToString());
                    item.SubItems.Add(flags.ToString());

                    if ((flags & GroupAttributes.Enabled) == GroupAttributes.Enabled)
                    {
                        item.BackColor = Color.LightGreen;
                    }
                    else if ((flags & GroupAttributes.UseForDenyOnly) == GroupAttributes.UseForDenyOnly)
                    {
                        item.BackColor = Color.LightSalmon;
                    }
                    item.Tag = group;
                    listView.Items.Add(item);
                }
            }
        }

        private void UpdateGroupList()
        {
            listViewGroups.Items.Clear();
            List<UserGroup> groups = new List<UserGroup>();
            groups.Add(_token.User);
            groups.AddRange(_token.Groups);

            PopulateGroupList(listViewGroups, groups);
        }

        private void UpdatePrivileges()
        {
            listViewPrivs.Items.Clear();
            foreach (TokenPrivilege priv in _token.Privileges)
            {
                ListViewItem item = new ListViewItem(priv.Name);
                bool enabled = false;
                string flags = "Disabled";

                if ((priv.Attributes & PrivilegeAttributes.Enabled) == PrivilegeAttributes.Enabled)
                {
                    enabled = true;
                    flags = "Enabled";
                }

                if ((priv.Attributes & PrivilegeAttributes.EnabledByDefault) == PrivilegeAttributes.EnabledByDefault)
                {
                    flags = "Default " + flags;
                }

                item.SubItems.Add(flags);
                item.SubItems.Add(priv.DisplayName);

                item.BackColor = enabled ? Color.LightGreen : Color.LightPink;
                item.Tag = priv;

                listViewPrivs.Items.Add(item);
            }
        }

        private void UpdateSecurityAttributes()
        {
            try
            {
                ClaimSecurityAttribute[] attrs = _token.SecurityAttributes;
                foreach (ClaimSecurityAttribute attr in attrs)
                {
                    TreeNode node = new TreeNode(attr.Name);
                    node.Nodes.Add(String.Format("Flags: {0}", attr.Flags));
                    int value_index = 0;
                    foreach (object value in attr.Values)
                    {
                        node.Nodes.Add(String.Format("Value {0}: {1}", value_index++, value));
                    }
                    treeViewSecurityAttributes.Nodes.Add(node);
                }
            }
            catch (NtException)
            {
            }
        }

        private void UpdateTokenData()
        {
            UserGroup user = _token.User;

            txtUsername.Text = user.ToString();
            txtUserSid.Text = user.Sid.ToString();

            TokenType tokentype = _token.TokenType;

            txtTokenType.Text = _token.TokenType.ToString();

            if (_token.TokenType== TokenType.Impersonation)
            {
                SecurityImpersonationLevel implevel = _token.ImpersonationLevel;
                txtImpLevel.Text = implevel.ToString();
            }
            else
            {
                txtImpLevel.Text = "N/A";
            }

            txtTokenId.Text = FormatLuid(_token.Id);
            txtModifiedId.Text = FormatLuid(_token.ModifiedId);
            txtAuthId.Text = FormatLuid(_token.AuthenticationId);
            if (Enum.IsDefined(typeof(TokenIntegrityLevel), _token.IntegrityLevel))
            {
                comboBoxIL.SelectedItem = _token.IntegrityLevel;
                comboBoxILForDup.SelectedItem = _token.IntegrityLevel;
            }
            else
            {
                comboBoxIL.Text = _token.IntegrityLevel.ToString();
                comboBoxILForDup.Text = _token.IntegrityLevel.ToString();
            }

            txtSessionId.Text = _token.SessionId.ToString();
            txtSourceName.Text = _token.Source.SourceName;
            txtSourceId.Text = FormatLuid(_token.Source.SourceIdentifier);
            TokenElevationType evtype = _token.ElevationType;
            txtElevationType.Text = evtype.ToString();
            txtIsElevated.Text = _token.Elevated.ToString();
            txtOriginLoginId.Text = FormatLuid(_token.Origin);

            btnLinkedToken.Enabled = evtype != TokenElevationType.Default;

            UpdateGroupList();

            txtPrimaryGroup.Text = _token.PrimaryGroup.Name;
            txtOwner.Text = _token.Owner.Name;

            Acl defdacl = _token.DefaultDalc;
            if (!defdacl.NullAcl)
            {
                foreach (Ace ace in defdacl)
                {
                    UserGroup group = new UserGroup(ace.Sid, GroupAttributes.None);

                    ListViewItem item = new ListViewItem(group.ToString());

                    uint mask = (uint)(GenericAccessRights.GenericAll | GenericAccessRights.GenericExecute | GenericAccessRights.GenericRead | GenericAccessRights.GenericWrite);
                    string maskstr;

                    if (((uint)ace.Mask & ~mask) != 0)
                    {
                        maskstr = String.Format("0x{0:X08}", ace.Mask);
                    }
                    else
                    {
                        GenericAccessRights generic = (GenericAccessRights)ace.Mask;
                        maskstr = generic.ToString();
                    }

                    item.SubItems.Add(maskstr);
                    item.SubItems.Add(ace.AceFlags.ToString());
                    item.SubItems.Add(ace.AceType.ToString());
                    listViewDefDacl.Items.Add(item);
                } 
            }
            else
            {
                listViewDefDacl.Items.Add("No Default DACL");
            }

            listViewDefDacl.AutoResizeColumns(ColumnHeaderAutoResizeStyle.ColumnContent);
            listViewDefDacl.AutoResizeColumns(ColumnHeaderAutoResizeStyle.HeaderSize);

            if (_token.Restricted)
            {
                PopulateGroupList(listViewRestrictedSids, _token.RestrictedSids);
            }
            else
            {
                tabControlMain.TabPages.Remove(tabPageRestricted);                
            }

            if (_token.AppContainer)
            {
                PopulateGroupList(listViewCapabilities, _token.Capabilities);
                txtACNumber.Text = _token.AppContainerNumber.ToString();
                txtPackageSid.Text = _token.AppContainerSid.Name;
            }
            else
            {
                tabControlMain.TabPages.Remove(tabPageAppContainer);
            }

            txtUIAccess.Text = _token.UiAccess.ToString();
            txtSandboxInert.Text = _token.SandboxInert.ToString();
            bool virtAllowed = _token.VirtualizationAllowed;
            txtVirtualizationAllowed.Text = virtAllowed.ToString();
            btnToggleVirtualizationEnabled.Enabled = virtAllowed;
            if (virtAllowed)
            {
                txtVirtualizationEnabled.Text = _token.VirtualizationEnabled.ToString();
            }
            else
            {
                txtVirtualizationEnabled.Text = "N/A";
            }

            txtMandatoryILPolicy.Text = _token.MandatoryPolicy.ToString();
            txtHandleAccess.Text = _token.GrantedAccess.ToString();
            UpdatePrivileges();
            UpdateSecurityAttributes();
        }

        public TokenForm(NtToken token)
        {
            InitializeComponent();
            this.Disposed += TokenForm_Disposed;
            _token = token;

            foreach (object v in Enum.GetValues(typeof(TokenIntegrityLevel)))
            {
                comboBoxIL.Items.Add(v);
                comboBoxILForDup.Items.Add(v);
            }

            UpdateTokenData();
            comboBoxImpLevel.Items.Add(SecurityImpersonationLevel.Anonymous);
            comboBoxImpLevel.Items.Add(SecurityImpersonationLevel.Identification);
            comboBoxImpLevel.Items.Add(SecurityImpersonationLevel.Impersonation);
            comboBoxImpLevel.Items.Add(SecurityImpersonationLevel.Delegation);
            comboBoxImpLevel.SelectedItem = SecurityImpersonationLevel.Impersonation;

            comboBoxTokenType.Items.Add(TokenType.Primary);
            comboBoxTokenType.Items.Add(TokenType.Impersonation);
            comboBoxTokenType.SelectedItem = TokenType.Impersonation;

            foreach (object v in Enum.GetValues(typeof(SaferLevel)))
            {
                comboBoxSaferLevel.Items.Add(v);
            }

            comboBoxSaferLevel.SelectedItem = SaferLevel.NormalUser;
        }

        void TokenForm_Disposed(object sender, EventArgs e)
        {
            _token.Dispose();
        }

        private void btnPermissions_Click(object sender, EventArgs e)
        {
            try
            {
                NativeBridge.EditSecurity(Handle, _token.Duplicate(TokenAccessRights.ReadControl), "Token");
            }
            catch (NtException ex)
            {
                MessageBox.Show(this, ex.Message, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        static List<TokenForm> _forms = new List<TokenForm>();
        static IWin32Window _main_form;

        public static void RegisterMainForm(MainForm window)
        {
            _main_form = window;
        }

        public static void OpenForm(NtToken token, bool copy)
        {
            if (token != null)
            {
                TokenForm form = new TokenForm(copy ? token.Duplicate() : token);

                _forms.Add(form);
                form.FormClosed += form_FormClosed;

                form.Show(_main_form);
            }
        }

        static void form_FormClosed(object sender, FormClosedEventArgs e)
        {
            TokenForm form = sender as TokenForm;

            if (form != null)
            {
                _forms.Remove((TokenForm)sender);
                form.Dispose();
            }
        }

        private void btnLinkedToken_Click(object sender, EventArgs e)
        {
            try
            {
                OpenForm(_token.GetLinkedToken(), false);
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, ex.Message, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void comboBoxTokenType_SelectedIndexChanged(object sender, EventArgs e)
        {
            if ((TokenType)comboBoxTokenType.SelectedItem != TokenType.Primary)
            {
                comboBoxImpLevel.Enabled = true;
            }
            else
            {
                comboBoxImpLevel.Enabled = false;
            }
        }

        private void btnDuplicate_Click(object sender, EventArgs e)
        {
            try
            {
                using (NtToken token = _token.DuplicateToken((TokenType)comboBoxTokenType.SelectedItem,
                        (SecurityImpersonationLevel)comboBoxImpLevel.SelectedItem, TokenAccessRights.MaximumAllowed))
                {
                    TokenIntegrityLevel il = GetILFromComboBox(comboBoxILForDup);
                    if (il != token.IntegrityLevel)
                    {
                        token.SetIntegrityLevel(il);
                    }
                    OpenForm(token, true);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, ex.Message, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void btnCreateProcess_Click(object sender, EventArgs e)
        {
            try
            {
                if (checkBoxUseWmi.Checked || checkBoxUseNetLogon.Checked)
                {
                    using (var token = _token.DuplicateToken(TokenType.Impersonation, SecurityImpersonationLevel.Impersonation, TokenAccessRights.MaximumAllowed))
                    {
                        token.SetDefaultDacl(new Acl(IntPtr.Zero, false));
                        using (var imp = token.Impersonate())
                        {
                            if (checkBoxUseWmi.Checked)
                            {
                                using (var managementClass = new ManagementClass(@"\\.\root\cimv2",
                                                                "Win32_Process",
                                                                 new ObjectGetOptions()))
                                {
                                    var inputParams = managementClass.GetMethodParameters("Create");

                                    inputParams["CommandLine"] = txtCommandLine.Text;
                                    var outParams = managementClass.InvokeMethod("Create",
                                                                                 inputParams,
                                                                                 new InvokeMethodOptions());
                                }
                            }
                            else
                            {
                                using (Win32Process.CreateProcessWithLogin("abc", "abc", "abc", CreateProcessLogonFlags.NetCredentialsOnly | CreateProcessLogonFlags.WithProfile,
                                    null, txtCommandLine.Text, CreateProcessFlags.None, @"WinSta0\Default"))
                                {
                                }
                            }
                        }
                    }
                }
                else
                {
                    using (TokenUtils.CreateProcessForToken(txtCommandLine.Text, _token, checkBoxMakeInteractive.Checked))
                    {
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, ex.Message, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }            
        }

        private void btnComputeSafer_Click(object sender, EventArgs e)
        {
            try
            {
                OpenForm(TokenUtils.GetTokenFromSaferLevel(_token,
                    (SaferLevel)comboBoxSaferLevel.SelectedItem, checkBoxSaferMakeInert.Checked), false);                  
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, ex.Message, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private static bool ParseNum(string str, out uint num)
        {
            num = 0;
            if (String.IsNullOrWhiteSpace(str))
            {
                return false;
            }

            if (str.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            {
                return uint.TryParse(str.Substring(2), NumberStyles.HexNumber, null, out num);
            }

            return uint.TryParse(str, out num);            
        }

        private static TokenIntegrityLevel GetILFromComboBox(ComboBox comboBox)
        {
            uint il_num;
            if (ParseNum(comboBox.Text, out il_num))
                return (TokenIntegrityLevel)il_num;

            if (comboBox.SelectedItem == null)
            {
                return TokenIntegrityLevel.Medium;
            }
            
            return (TokenIntegrityLevel)comboBox.SelectedItem;
        }

        private void comboBoxIL_SelectedIndexChanged(object sender, EventArgs e)
        {
            TokenIntegrityLevel il = GetILFromComboBox(comboBoxIL);

            if (_token.IntegrityLevel!= il)
            {
                btnSetIL.Enabled = true;
            }
            else
            {
                btnSetIL.Enabled = false;
            }
        }

        private void btnSetIL_Click(object sender, EventArgs e)
        {
            TokenIntegrityLevel il = GetILFromComboBox(comboBoxIL);
            if (_token.IntegrityLevel!= il)
            {
                try
                {
                    _token.SetIntegrityLevel(il);
                    btnSetIL.Enabled = false;
                    UpdatePrivileges();
                }
                catch (Exception ex)
                {
                    MessageBox.Show(this, ex.Message, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
            }
        }

        private void btnBrowse_Click(object sender, EventArgs e)
        {
            using (SaveFileDialog dlg = new SaveFileDialog())
            {
                dlg.FileName = txtFilePath.Text;
                dlg.Filter = "All Files (*.*)|*.*";

                if (dlg.ShowDialog(this) == DialogResult.OK)
                {
                    txtFilePath.Text = dlg.FileName;
                }
            }
        }

        private void btnCreate_Click(object sender, EventArgs e)
        {
            try
            {
                using (NtToken token = _token.DuplicateToken(TokenType.Impersonation,
                    SecurityImpersonationLevel.Impersonation, TokenAccessRights.MaximumAllowed))
                {
                    using (var imp = token.Impersonate())
                    {
                        File.WriteAllText(txtFilePath.Text, txtFileContents.Text);
                    }

                    MessageBox.Show(this, "Success", "Success", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, ex.Message, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        static bool AllPrivsEnabled(IEnumerable<TokenPrivilege> privs)
        {            
            foreach (TokenPrivilege priv in privs)
            {
                if (!priv.Enabled)
                {
                    return false;
                }
            }
            return true;
        }

        private void contextMenuStripPrivileges_Opening(object sender, CancelEventArgs e)
        {
            if (listViewPrivs.SelectedItems.Count > 0)
            {
                if (AllPrivsEnabled(GetSelectedItemTags(listViewPrivs).OfType<TokenPrivilege>()))
                {
                    enablePrivilegeToolStripMenuItem.Text = "Disable Privilege";
                }
                else
                {
                    enablePrivilegeToolStripMenuItem.Text = "Enable Privilege";
                }
                enablePrivilegeToolStripMenuItem.Enabled = true;
            }
            else
            {
                enablePrivilegeToolStripMenuItem.Enabled = false;
            }
        }

        private void ModifyPrivileges(IEnumerable<TokenPrivilege> privs, PrivilegeAttributes attributes)
        {
            bool multi = privs.Count() > 1;
            foreach (TokenPrivilege priv in privs)
            {
                try
                {
                    _token.SetPrivilege(priv.Luid, attributes);
                }
                catch (Exception ex)
                {
                    if (!multi)
                    {
                        MessageBox.Show(this, ex.Message, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    }
                }
            }
            UpdatePrivileges();
        }

        private void enablePrivilegeToolStripMenuItem_Click(object sender, EventArgs e)
        {
            if (listViewPrivs.SelectedItems.Count > 0)
            {
                IEnumerable<TokenPrivilege> privs = GetSelectedItemTags(listViewPrivs).OfType<TokenPrivilege>();
                bool all_enabled = AllPrivsEnabled(privs);
                PrivilegeAttributes attributes = all_enabled ? PrivilegeAttributes.Disabled : PrivilegeAttributes.Enabled;
                ModifyPrivileges(privs, attributes);
            }
        }

        private static void SelectAllItems(ListView listView)
        {
            foreach (ListViewItem item in listView.Items)
            {
                item.Selected = true;
            }
        }

        private void selectAllToolStripMenuItem_Click(object sender, EventArgs e)
        {
            SelectAllItems(listViewPrivs);
        }

        private void selectAllGroupsToolStripMenuItem_Click(object sender, EventArgs e)
        {
            SelectAllItems(listViewGroups);
        }

        List<UserGroup> GetSelectedModifiableGroups()
        {
            List<UserGroup> groups = new List<UserGroup>();
            foreach (UserGroup group in
                    listViewGroups.SelectedItems.OfType<ListViewItem>().Select(i => i.Tag))
            {
                if (group != null && !group.Mandatory && !group.DenyOnly)
                {
                    groups.Add(group);
                }
            }
            return groups;
        }

        static bool AllGroupsEnabled(IEnumerable<UserGroup> groups)
        {
            foreach (UserGroup group in groups)
            {
                if (!group.Enabled)
                {
                    return false;
                }
            }
            return true;
        }

        private void enableGroupToolStripMenuItem_Click(object sender, EventArgs e)
        {
            List<UserGroup> groups = GetSelectedModifiableGroups();
            if (groups.Count > 0)
            {
                bool multi_enable = groups.Count > 1;
                bool all_enabled = AllGroupsEnabled(groups);

                foreach (UserGroup group in groups)
                {
                    try
                    {
                        if (group != null)
                        {
                            _token.SetGroup(group.Sid, all_enabled ? GroupAttributes.Enabled : GroupAttributes.None);
                        }
                    }
                    catch (NtException ex)
                    {
                        if (!multi_enable)
                        {
                            MessageBox.Show(this, ex.Message, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                        }
                    }
                }
                UpdateGroupList();
            }
            else
            {
                MessageBox.Show(this, "No Modifable Groups Selected", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void contextMenuStripGroups_Opening(object sender, CancelEventArgs e)
        {
            List<UserGroup> groups = GetSelectedModifiableGroups();
            if (groups.Count > 0)
            {
                if (AllGroupsEnabled(groups))
                {
                    enableGroupToolStripMenuItem.Text = "Disable Group";
                }
                else
                {
                    enableGroupToolStripMenuItem.Text = "Enable Group";
                }
                enableGroupToolStripMenuItem.Enabled = true;
            }
            else
            {
                enableGroupToolStripMenuItem.Enabled = false;
            }
        }

        private void btnCreateSandbox_Click(object sender, EventArgs e)
        {
            using (CreateSandboxTokenForm form = new CreateSandboxTokenForm(_token))
            {
                if (form.ShowDialog(this) == DialogResult.OK)
                {
                    OpenForm(form.Token, false);
                }
            }
        }

        private void btnImpersonate_Click(object sender, EventArgs e)
        {
            SecurityImpersonationLevel implevel = SecurityImpersonationLevel.Impersonation;
            try
            {
                if (_token.TokenType== TokenType.Impersonation)
                {
                    implevel = _token.ImpersonationLevel;       
                }

                using (NtToken token = _token.DuplicateToken(TokenType.Impersonation, implevel, TokenAccessRights.MaximumAllowed))
                {
                    TokenIntegrityLevel il = GetILFromComboBox(comboBoxILForDup);
                    if (il != token.IntegrityLevel)
                    {
                        token.SetIntegrityLevel(il);
                    }

                    NtToken imptoken = null;
                    using (var imp = token.Impersonate())
                    {
                        imptoken = NtThread.Current.OpenToken();
                    }
                    if (imptoken != null)
                    {
                        OpenForm(imptoken, false);
                    }
                    else
                    {
                        MessageBox.Show(this, "Couldn't open thread token", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, ex.Message, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void comboBoxIL_TextUpdate(object sender, EventArgs e)
        {
            comboBoxIL_SelectedIndexChanged(sender, e);
        }

        private IEnumerable<object> GetSelectedItemTags(ListView listView)
        {
            return listView.SelectedItems.OfType<ListViewItem>().Select(i => i.Tag);
        }

        private void removePrivilegeToolStripMenuItem_Click(object sender, EventArgs e)
        {
            ModifyPrivileges(GetSelectedItemTags(listViewPrivs).OfType<TokenPrivilege>(), 
                PrivilegeAttributes.Removed);
        }

        private void btnToggleUIAccess_Click(object sender, EventArgs e)
        {
            try
            {
                _token.SetUiAccess(!_token.UiAccess);
                txtUIAccess.Text = _token.UiAccess.ToString();
            }
            catch (NtException ex)
            {
                MessageBox.Show(this, ex.Message, 
                    "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void btnToggleVirtualizationEnabled_Click(object sender, EventArgs e)
        {
            try
            {
                _token.SetVirtualizationEnabled(!_token.VirtualizationEnabled);
                txtVirtualizationEnabled.Text = _token.VirtualizationEnabled.ToString();
            }
            catch (NtException ex)
            {
                MessageBox.Show(this, ex.Message,
                    "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }
    }
}
