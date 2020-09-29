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

using NtApiDotNet;
using NtApiDotNet.Win32;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Drawing;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Management;
using System.Runtime.InteropServices;
using System.Text;
using System.Windows.Forms;

namespace TokenViewer
{
    public partial class TokenForm : Form
    {
        private NtToken _token;

        private static void PopulateGroupList(ListView listView, IEnumerable<UserGroup> groups, bool filter_il)
        {
            foreach (UserGroup group in groups)
            {
                GroupAttributes flags = group.Attributes & ~(GroupAttributes.EnabledByDefault);

                if (filter_il && flags.HasFlag(GroupAttributes.Integrity))
                {
                    continue;
                }

                ListViewItem item = new ListViewItem(group.ToString());
                item.SubItems.Add(flags.ToString());

                if (flags.HasFlag(GroupAttributes.Enabled))
                {
                    item.BackColor = Color.LightGreen;
                }
                else if (flags.HasFlag(GroupAttributes.UseForDenyOnly))
                {
                    item.BackColor = Color.LightSalmon;
                }
                item.Tag = group;
                listView.Items.Add(item);
            }
            listView.AutoResizeColumns(ColumnHeaderAutoResizeStyle.ColumnContent);
            listView.AutoResizeColumns(ColumnHeaderAutoResizeStyle.HeaderSize);
        }

        private void UpdateGroupList()
        {
            listViewGroups.Items.Clear();
            List<UserGroup> groups = new List<UserGroup>();
            groups.Add(_token.User);
            groups.AddRange(_token.Groups);

            PopulateGroupList(listViewGroups, groups, true);
        }

        private void UpdatePrivileges()
        {
            listViewPrivs.Items.Clear();
            foreach (TokenPrivilege priv in _token.Privileges)
            {
                ListViewItem item = new ListViewItem(priv.Name);
                bool enabled = false;
                string flags = "Disabled";

                if (priv.Attributes.HasFlag(PrivilegeAttributes.Enabled))
                {
                    enabled = true;
                    flags = "Enabled";
                }

                if (priv.Attributes.HasFlag(PrivilegeAttributes.EnabledByDefault))
                {
                    flags = "Default " + flags;
                }

                item.SubItems.Add(flags);
                item.SubItems.Add(priv.DisplayName);

                item.BackColor = enabled ? Color.LightGreen : Color.LightPink;
                item.Tag = priv;

                listViewPrivs.Items.Add(item);
            }
            listViewPrivs.AutoResizeColumns(ColumnHeaderAutoResizeStyle.ColumnContent);
            listViewPrivs.AutoResizeColumns(ColumnHeaderAutoResizeStyle.HeaderSize);
        }

        private static string FormatAttributeValue(object value)
        {
            if (value is byte[] bytes)
            {
                StringBuilder builder = new StringBuilder();
                builder.AppendFormat("Length {0} - {{", bytes.Length);
                int count = bytes.Length;
                builder.Append(string.Join(", ", bytes.Take(count > 16 ? 16 : count).Select(b => $"0x{b:X02}")));

                if (count > 16)
                {
                    builder.Append(", ...");
                }
                builder.Append("}");
                return builder.ToString();
            }
            else if (value is ulong l)
            {
                return $"{l:X016}";
            }

            return value.ToString();
        }

        private void UpdateSecurityAttributes(TabPage tab_page, TreeView treeView, SecurityAttributeType type)
        {
            var attrs = _token.GetSecurityAttributes(type, false);
            if (!attrs.IsSuccess || attrs.Result.Length == 0)
            {
                tabControlSecurityAttributes.TabPages.Remove(tab_page);
            }
            treeView.Nodes.Clear();
            foreach (ClaimSecurityAttribute attr in attrs.Result)
            {
                TreeNode node = new TreeNode(attr.Name);
                node.Nodes.Add($"Flags: {attr.Flags}");
                node.Nodes.Add($"Type: {attr.ValueType}");
                int value_index = 0;
                foreach (object value in attr.Values)
                {
                    node.Nodes.Add($"Value {value_index++}: {FormatAttributeValue(value)}");
                }
                treeView.Nodes.Add(node);
            }
            foreach (TreeNode node in treeView.Nodes)
            {
                node.Expand();
            }
        }

        private void UpdateTokenFlags()
        {
            txtTokenFlags.Text = _token.Flags.ToString();
        }

        private void UpdateTokenData(ProcessTokenEntry process)
        {
            UserGroup user = _token.User;

            txtUsername.Text = user.ToString();
            txtUserSid.Text = user.Sid.ToString();

            TokenType tokentype = _token.TokenType;

            txtTokenType.Text = tokentype.ToString();

            if (tokentype == TokenType.Impersonation)
            {
                txtImpLevel.Text = _token.ImpersonationLevel.ToString();
            }
            else
            {
                txtImpLevel.Text = "N/A";
            }

            txtTokenId.Text = _token.Id.ToString();
            txtModifiedId.Text = _token.ModifiedId.ToString();
            txtAuthId.Text = _token.AuthenticationId.ToString();
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
            if (_token.IsAccessGranted(TokenAccessRights.QuerySource))
            {
                txtSourceName.Text = _token.Source.SourceName;
                txtSourceId.Text = _token.Source.SourceIdentifier.ToString();
            }
            else
            {
                txtSourceName.Text = "N/A";
                txtSourceId.Text = "N/A";
            }
            TokenElevationType evtype = _token.ElevationType;
            txtElevationType.Text = evtype.ToString();
            txtIsElevated.Text = _token.Elevated.ToString();
            txtOriginLoginId.Text = _token.Origin.ToString();

            btnLinkedToken.Enabled = evtype != TokenElevationType.Default;
            btnLinkedToken.Visible = btnLinkedToken.Enabled;

            UpdateGroupList();

            txtPrimaryGroup.Text = _token.PrimaryGroup.Name;
            txtOwner.Text = _token.Owner.Name;

            Acl defdacl = _token.DefaultDacl;
            if (!defdacl.NullAcl)
            {
                foreach (Ace ace in defdacl)
                {
                    UserGroup group = new UserGroup(ace.Sid, GroupAttributes.None);

                    ListViewItem item = new ListViewItem(group.ToString());

                    AccessMask mask = GenericAccessRights.GenericAll | GenericAccessRights.GenericExecute 
                        | GenericAccessRights.GenericRead | GenericAccessRights.GenericWrite 
                        | GenericAccessRights.AccessSystemSecurity | GenericAccessRights.Delete | GenericAccessRights.ReadControl
                        | GenericAccessRights.Synchronize | GenericAccessRights.WriteDac | GenericAccessRights.WriteOwner;
                    string maskstr;

                    if ((ace.Mask & ~mask).HasAccess)
                    {
                        maskstr = $"0x{ace.Mask:X08}";
                    }
                    else
                    {
                        maskstr = ace.Mask.ToGenericAccess().ToString();
                    }

                    item.SubItems.Add(maskstr);
                    item.SubItems.Add(ace.Flags.ToString());
                    item.SubItems.Add(ace.Type.ToString());
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
                PopulateGroupList(listViewRestrictedSids, _token.RestrictedSids, false);
                if (_token.WriteRestricted)
                {
                    tabPageRestricted.Text = "Write Restricted SIDs";
                }
            }
            else
            {
                tabControlMain.TabPages.Remove(tabPageRestricted);
            }

            if (_token.AppContainer)
            {
                PopulateGroupList(listViewCapabilities, _token.Capabilities, false);
                txtACNumber.Text = _token.AppContainerNumber.ToString();
                txtPackageName.Text = _token.AppContainerSid.Name;
                txtPackageSid.Text = _token.AppContainerSid.ToString();
            }
            else
            {
                tabControlMain.TabPages.Remove(tabPageAppContainer);
            }

            if (process == null)
            {
                tabControlMain.TabPages.Remove(tabPageTokenSource);
            }
            else
            {
                txtProcessId.Text = process.ProcessId.ToString();
                txtProcessImagePath.Text = process.ImagePath;
                txtProcessCommandLine.Text = process.CommandLine;
                if (process is ThreadTokenEntry thread)
                {
                    txtThreadId.Text = thread.ThreadId.ToString();
                    txtThreadName.Text = thread.ThreadName;
                }
                else
                {
                    groupThread.Visible = false;
                }
            }

            txtUIAccess.Text = _token.UIAccess.ToString();
            txtSandboxInert.Text = _token.SandboxInert.ToString();
            bool virtAllowed = _token.VirtualizationAllowed;
            txtVirtualizationAllowed.Text = virtAllowed.ToString();
            btnToggleVirtualizationEnabled.Enabled = virtAllowed;
            btnToggleVirtualizationEnabled.Visible = virtAllowed;
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
            Sid trust_level = _token.TrustLevel;
            txtTrustLevel.Text = trust_level != null ? trust_level.Name : "N/A";
            UpdateTokenFlags();
            UpdatePrivileges();
            UpdateSecurityAttributes(tabPageLocalSecurityAttributes, treeViewLocalSecurityAttributes, SecurityAttributeType.Local);
            UpdateSecurityAttributes(tabPageUserClaimSecurityAttributes, treeViewUserClaimSecurityAttributes, SecurityAttributeType.User);
            UpdateSecurityAttributes(tabPageDeviceClaimSecurityAttributes, treeViewDeviceClaimSecurityAttributes, SecurityAttributeType.Device);
            if (_token.DeviceGroups.Length > 0)
            {
                PopulateGroupList(listViewDeviceGroup, _token.DeviceGroups, false);
            }
            else
            {
                tabControlSecurityAttributes.TabPages.Remove(tabPageDeviceGroup);
            }
            if (tabControlSecurityAttributes.TabCount == 0)
            {
                lblSecurityAttributes.Visible = false;
            }

            if (_token.IsAccessGranted(TokenAccessRights.ReadControl))
            {
                securityDescriptorViewerControl.SetSecurityDescriptor(_token.SecurityDescriptor, _token.NtType, _token.NtType.ValidAccess);
            }
            else
            {
                tabControlMain.TabPages.Remove(tabPageSecurity);
            }
        }

        private static string GetFormText(NtToken token, string text)
        {
            StringBuilder builder = new StringBuilder();
            if (!string.IsNullOrWhiteSpace(text))
            {
                builder.AppendFormat("{0} - ", text);
            }
            builder.AppendFormat("User {0} - TokenId {1}",
                token.User.Sid.Name, token.Id);
            return builder.ToString();
        }

        public TokenForm(NtToken token) 
            : this(token, null)
        {
        }

        public TokenForm(NtToken token, string text) 
            : this(null, token, text)
        {
        }

        private TokenForm(ProcessTokenEntry process, NtToken token, string text)
        {
            InitializeComponent();
            this.Disposed += TokenForm_Disposed;
            _token = token;
            Text = GetFormText(token, text);

            foreach (object v in Enum.GetValues(typeof(TokenIntegrityLevel)))
            {
                comboBoxIL.Items.Add(v);
                comboBoxILForDup.Items.Add(v);
            }

            UpdateTokenData(process);
            listViewGroups.ListViewItemSorter = new ListItemComparer(0);
            listViewPrivs.ListViewItemSorter = new ListItemComparer(0);
            listViewRestrictedSids.ListViewItemSorter = new ListItemComparer(0);
            listViewCapabilities.ListViewItemSorter = new ListItemComparer(0);

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

        internal TokenForm(ProcessTokenEntry process, string text, bool thread)
            : this(process, thread ? ((ThreadTokenEntry)process).ThreadToken : process.ProcessToken, text)
        {
        }

        void TokenForm_Disposed(object sender, EventArgs e)
        {
            _token.Dispose();
        }

        private bool ShowTokenPermissions(TokenAccessRights access, bool throw_on_error)
        {
            using (var result = _token.Duplicate(access, AttributeFlags.None, DuplicateObjectOptions.None, throw_on_error))
            {
                if (result.IsSuccess)
                {
                    Win32Utils.EditSecurity(Handle,
                        result.Result,
                        "Token", false);
                    return true;
                }
            }
            return false;
        }

        private void btnEditPermissions_Click(object sender, EventArgs e)
        {
            try
            {
                if (!ShowTokenPermissions(TokenAccessRights.ReadControl | TokenAccessRights.WriteDac, false))
                {
                    ShowTokenPermissions(TokenAccessRights.ReadControl, true);
                }
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

        private static void OpenForm(TokenForm form)
        {
            _forms.Add(form);
            form.FormClosed += form_FormClosed;
            form.Show(_main_form);
        }

        public static void OpenForm(NtToken token, string text, bool copy)
        {
            if (token != null)
            {
                OpenForm(new TokenForm(copy ? token.Duplicate() : token, text));
            }
        }

        internal static void OpenForm(ProcessTokenEntry process, string text, bool copy, bool thread)
        {
            if (process != null)
            {
                OpenForm(new TokenForm(copy ? process.Clone() : process, text, thread));
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
                OpenForm(_token.GetLinkedToken(), "Linked", false);
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
                    OpenForm(token, "Duplicate", true);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, ex.Message, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        static NtToken CreateProcessForToken(string cmdline, NtToken token, bool make_interactive)
        {
            using (NtToken newtoken = token.DuplicateToken(TokenType.Primary, SecurityImpersonationLevel.Anonymous, TokenAccessRights.MaximumAllowed))
            {
                string desktop = null;
                if (make_interactive)
                {
                    desktop = @"WinSta0\Default";
                    newtoken.SetSessionId(NtProcess.Current.SessionId);
                }

                using (Win32Process process = Win32Process.CreateProcessAsUser(newtoken, null, cmdline, CreateProcessFlags.None, desktop))
                {
                    return process.Process.OpenToken();
                }
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
                                var config = new Win32ProcessConfig
                                {
                                    CommandLine = txtCommandLine.Text,
                                    Desktop = @"WinSta0\Default"
                                };
                                using (Win32Process.CreateProcessWithLogon("abc", "abc", "abc", 
                                    CreateProcessLogonFlags.NetCredentialsOnly | CreateProcessLogonFlags.WithProfile, config))
                                {
                                }
                            }
                        }
                    }
                }
                else
                {
                    using (CreateProcessForToken(txtCommandLine.Text, _token, checkBoxMakeInteractive.Checked))
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
                    (SaferLevel)comboBoxSaferLevel.SelectedItem, checkBoxSaferMakeInert.Checked), "Safer", false);                  
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, ex.Message, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private static bool ParseNum(string str, out uint num)
        {
            num = 0;
            if (string.IsNullOrWhiteSpace(str))
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
                    OpenForm(form.Token, "Sandbox", false);
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
                        OpenForm(imptoken, "Impersonation", false);
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
                _token.SetUIAccess(!_token.UIAccess);
                txtUIAccess.Text = _token.UIAccess.ToString();
                UpdateTokenFlags();
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
                UpdateTokenFlags();
            }
            catch (NtException ex)
            {
                MessageBox.Show(this, ex.Message,
                    "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void listView_ColumnClick(object sender, ColumnClickEventArgs e)
        {
            ListItemComparer.UpdateListComparer(sender as ListView, e.Column);
        }

        private static void CopyToClipboard(StringBuilder builder)
        {
            CopyToClipboard(builder.ToString());
        }

        private static void CopyToClipboard(string builder)
        {
            try
            {
                Clipboard.SetText(builder.ToString());
            }
            catch (ExternalException)
            {
            }
        }

        private static void CopyListViewItems(ListView list, Func<ListViewItem, string> formatter)
        {
            if (list.SelectedItems.Count > 0)
            {
                StringBuilder builder = new StringBuilder();
                foreach (ListViewItem item in list.SelectedItems)
                {
                    string format = formatter(item);
                    if (format != null)
                    {
                        builder.AppendLine(formatter(item));
                    }
                }

                CopyToClipboard(builder);
            }
        }

        private static Control GetParentControl(object sender)
        {
            if (sender is ToolStripMenuItem item)
            {
                if (item.Owner is ContextMenuStrip menu)
                {
                    return menu.SourceControl;
                }
            }
            return null;
        }

        private void CopyListViewItems(object sender, EventArgs e)
        {
            if (GetParentControl(sender) is ListView list)
            {
                CopyListViewItems(list, item => string.Join(" - ", item.SubItems.Cast<ListViewItem.ListViewSubItem>().Select(i => i.Text)));
            }
        }
        
        private void CopySidListViewItems(object sender, EventArgs e)
        {
            if (GetParentControl(sender) is ListView list)
            {
                CopyListViewItems(list, item =>
                {
                    if (item.Tag is UserGroup group) {
                        return group.Sid.ToString();
                    }
                    return null;
                });
            }
        }

        private void SelectAllListViewItems(object sender, EventArgs e)
        {
            if (GetParentControl(sender) is ListView list)
            {
                SelectAllItems(list);
            }
        }

        private void copyAsSDDLToolStripMenuItem_Click(object sender, EventArgs e)
        {
            SecurityDescriptor sd = new SecurityDescriptor();
            sd.Owner = new SecurityDescriptorSid(_token.Owner, true);
            sd.Group = new SecurityDescriptorSid(_token.PrimaryGroup, true);
            sd.Dacl = _token.DefaultDacl;
            CopyToClipboard(sd.ToSddl());
        }

        private void selectAllDaclToolStripMenuItem_Click(object sender, EventArgs e)
        {
            SelectAllItems(listViewDefDacl);
        }
    }
}
