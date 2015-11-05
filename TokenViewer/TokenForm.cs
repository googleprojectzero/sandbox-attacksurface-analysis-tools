//  Copyright 2015 Google Inc. All Rights Reserved.
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//  http ://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

using HandleUtils;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Drawing;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Windows.Forms;
using System.IO;
using TokenLibrary;

namespace TokenViewer
{
    public partial class TokenForm : Form
    {
        private UserToken _token;

        static string FormatLuid(ulong luid)
        {
            return String.Format("{0:X08}-{1:X08}",
                luid >> 32, luid & 0xFFFFFFFFUL);
        }

        private static void PopulateGroupList(ListView listView, UserGroup[] groups)
        {
            foreach (UserGroup group in groups)
            {
                GroupFlags flags = group.Flags & ~(GroupFlags.EnabledByDefault);

                if ((flags & GroupFlags.Integrity) == GroupFlags.None)
                {
                    ListViewItem item = new ListViewItem(group.GetName());
                    item.SubItems.Add(flags.ToString());

                    if ((flags & GroupFlags.Enabled) == GroupFlags.Enabled)
                    {
                        item.BackColor = Color.LightGreen;
                    }
                    else if ((flags & GroupFlags.UseForDenyOnly) == GroupFlags.UseForDenyOnly)
                    {
                        item.BackColor = Color.LightSalmon;
                    }

                    listView.Items.Add(item);
                }
            }
        }

        private void UpdatePrivileges()
        {
            listViewPrivs.Items.Clear();
            foreach (TokenPrivilege priv in _token.GetPrivileges())
            {
                ListViewItem item = new ListViewItem(priv.Name);
                bool enabled = false;
                string flags = "Disabled";

                if ((priv.Flags & TokenPrivilegeFlags.Enabled) == TokenPrivilegeFlags.Enabled)
                {
                    enabled = true;
                    flags = "Enabled";
                }

                if ((priv.Flags & TokenPrivilegeFlags.EnabledByDefault) == TokenPrivilegeFlags.EnabledByDefault)
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

        private void UpdateTokenData()
        {
            UserGroup user = _token.GetUser();

            txtUsername.Text = user.GetName();
            txtUserSid.Text = user.Sid.ToString();

            TokenType tokentype = _token.GetTokenType();

            txtTokenType.Text = _token.GetTokenType().ToString();

            TokenLibrary.TokenImpersonationLevel implevel = _token.GetImpersonationLevel();

            txtImpLevel.Text = implevel.ToString();            

            txtTokenId.Text = FormatLuid(_token.GetTokenId());
            txtModifiedId.Text = FormatLuid(_token.GetModifiedId());
            txtAuthId.Text = FormatLuid(_token.GetAuthenticationId());
            if (Enum.IsDefined(typeof(TokenLibrary.TokenIntegrityLevel), _token.GetTokenIntegrityLevel()))
            {
                comboBoxIL.SelectedItem = _token.GetTokenIntegrityLevel();
                comboBoxILForDup.SelectedItem = _token.GetTokenIntegrityLevel();
            }
            else
            {
                comboBoxIL.Text = _token.GetTokenIntegrityLevel().ToString();
                comboBoxILForDup.Text = _token.GetTokenIntegrityLevel().ToString();
            }

            txtSessionId.Text = _token.GetSessionId().ToString();
            txtSourceName.Text = _token.GetSourceName();
            txtSourceId.Text = FormatLuid(_token.GetSourceId());
            TokenElevationType evtype = _token.GetElevationType();
            txtElevationType.Text = evtype.ToString();
            txtOriginLoginId.Text = FormatLuid(_token.GetTokenOriginId());

            btnLinkedToken.Enabled = evtype != TokenElevationType.Default;

            PopulateGroupList(listViewGroups, _token.GetGroups());

            txtPrimaryGroup.Text = _token.GetPrimaryGroup().GetName();
            txtOwner.Text = _token.GetDefaultOwner().GetName();

            RawAcl defdacl = _token.GetDefaultDacl();
            if (defdacl != null)
            {
                foreach (GenericAce ace in defdacl)
                {
                    KnownAce kace = ace as KnownAce;
                    if (kace != null)
                    {
                        UserGroup group = new UserGroup(kace.SecurityIdentifier, GroupFlags.None);

                        ListViewItem item = new ListViewItem(group.GetName());

                        uint mask = (uint)(GenericAccessRights.GenericAll | GenericAccessRights.GenericExecute | GenericAccessRights.GenericRead | GenericAccessRights.GenericWrite);
                        string maskstr;

                        if (((uint)kace.AccessMask & ~mask) != 0)
                        {
                            maskstr = String.Format("0x{0:X08}", kace.AccessMask);
                        }
                        else
                        {
                            GenericAccessRights generic = (GenericAccessRights)kace.AccessMask;
                            maskstr = generic.ToString();
                        }

                        item.SubItems.Add(maskstr);
                        item.SubItems.Add(kace.AceFlags.ToString());
                        item.SubItems.Add(kace.AceType.ToString());
                        listViewDefDacl.Items.Add(item);
                    }
                } 
            }
            else
            {
                listViewDefDacl.Items.Add("No Default DACL");
            }

            listViewDefDacl.AutoResizeColumns(ColumnHeaderAutoResizeStyle.ColumnContent);
            listViewDefDacl.AutoResizeColumns(ColumnHeaderAutoResizeStyle.HeaderSize);

            if (_token.IsRestricted())
            {
                PopulateGroupList(listViewRestrictedSids, _token.GetRestrictedSids());
            }
            else
            {
                tabControlMain.TabPages.Remove(tabPageRestricted);                
            }

            if (_token.IsAppContainer())
            {
                PopulateGroupList(listViewCapabilities, _token.GetCapabilities());
                txtACNumber.Text = _token.GetAppContainerNumber().ToString();
                txtPackageSid.Text = _token.GetPackageSid().GetName();
            }
            else
            {
                tabControlMain.TabPages.Remove(tabPageAppContainer);
            }

            txtUIAccess.Text = _token.IsUIAccess().ToString();
            txtSandboxInert.Text = _token.IsSandboxInert().ToString();
            bool virtAllowed = _token.IsVirtualizationAllowed();
            txtVirtualizationAllowed.Text = virtAllowed.ToString();
            if (virtAllowed)
            {
                txtVirtualizationEnabled.Text = _token.IsVirtualizationEnabled().ToString();
            }
            else
            {
                txtVirtualizationEnabled.Text = "N/A";
            }

            txtMandatoryILPolicy.Text = _token.GetIntegrityLevelPolicy().ToString();
            UpdatePrivileges();            
        }

        public TokenForm(UserToken token)
        {
            InitializeComponent();
            this.Disposed += TokenForm_Disposed;
            _token = token;

            foreach (object v in Enum.GetValues(typeof(TokenLibrary.TokenIntegrityLevel)))
            {
                comboBoxIL.Items.Add(v);
                comboBoxILForDup.Items.Add(v);
            }

            UpdateTokenData();
            comboBoxImpLevel.Items.Add(TokenLibrary.TokenImpersonationLevel.Anonymous);
            comboBoxImpLevel.Items.Add(TokenLibrary.TokenImpersonationLevel.Identification);
            comboBoxImpLevel.Items.Add(TokenLibrary.TokenImpersonationLevel.Impersonation);
            comboBoxImpLevel.Items.Add(TokenLibrary.TokenImpersonationLevel.Delegation);
            comboBoxImpLevel.SelectedItem = TokenLibrary.TokenImpersonationLevel.Impersonation;

            comboBoxTokenType.Items.Add(TokenLibrary.TokenType.Primary);
            comboBoxTokenType.Items.Add(TokenLibrary.TokenType.Impersonation);
            comboBoxTokenType.SelectedItem = TokenLibrary.TokenType.Impersonation;

            foreach (object v in Enum.GetValues(typeof(TokenLibrary.SaferLevel)))
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
                NativeBridge.EditSecurity(Handle, _token.Handle, "Token", "Token", false);
            }
            catch (Exception)
            {
            }
        }

        static List<TokenForm> _forms = new List<TokenForm>();

        public static void OpenForm(IWin32Window parent, UserToken token, bool copy)
        {
            if (token != null)
            {
                TokenForm form = new TokenForm(copy ? token.DuplicateHandle() : token);

                _forms.Add(form);
                form.FormClosed += form_FormClosed;

                form.Show(parent);
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
                OpenForm(this, _token.GetLinkedToken(), false);
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, ex.Message, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void comboBoxTokenType_SelectedIndexChanged(object sender, EventArgs e)
        {
            if ((TokenLibrary.TokenType)comboBoxTokenType.SelectedItem != TokenLibrary.TokenType.Primary)
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
                using (UserToken token = _token.DuplicateToken((TokenType)comboBoxTokenType.SelectedItem,
                    (TokenLibrary.TokenImpersonationLevel)comboBoxImpLevel.SelectedItem,
                    (TokenLibrary.TokenIntegrityLevel)comboBoxILForDup.SelectedItem))
                {
                    if (checkBoxLuaToken.Checked)
                    {
                        OpenForm(this, token.MakeLuaToken(), false);
                    }
                    else
                    {
                        OpenForm(this, token, true);
                    }
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
                using(UserToken token = TokenUtils.CreateProcessForToken(txtCommandLine.Text, _token, checkBoxMakeInteractive.Checked))
                {
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
                OpenForm(this, TokenUtils.GetTokenFromSaferLevel(_token,
                    (SaferLevel)comboBoxSaferLevel.SelectedItem, checkBoxSaferMakeInert.Checked), false);                  
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, ex.Message, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void comboBoxIL_SelectedIndexChanged(object sender, EventArgs e)
        {
            if (comboBoxIL.SelectedItem != null)
            {
                TokenIntegrityLevel il = (TokenIntegrityLevel)comboBoxIL.SelectedItem;

                if (_token.GetTokenIntegrityLevel() != il)
                {
                    btnSetIL.Enabled = true;
                }
                else
                {
                    btnSetIL.Enabled = false;
                }
            }
        }

        private void btnSetIL_Click(object sender, EventArgs e)
        {
            if (comboBoxIL.SelectedItem != null)
            {
                TokenIntegrityLevel il = (TokenIntegrityLevel)comboBoxIL.SelectedItem;

                if (_token.GetTokenIntegrityLevel() != il)
                {
                    try
                    {
                        _token.SetTokenIntegrityLevel(il);
                        btnSetIL.Enabled = false;
                        UpdatePrivileges();
                    }
                    catch (Exception ex)
                    {
                        MessageBox.Show(this, ex.Message, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    }
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
                using (UserToken token = _token.DuplicateToken(TokenType.Impersonation, 
                    TokenLibrary.TokenImpersonationLevel.Impersonation))
                {
                    using (ImpersonateProcess imp = token.Impersonate())
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

        private void contextMenuStripPrivileges_Opening(object sender, CancelEventArgs e)
        {
            if (listViewPrivs.SelectedItems.Count > 0)
            {
                TokenPrivilege priv = listViewPrivs.SelectedItems[0].Tag as TokenPrivilege;
                if (priv != null)
                {
                    if (priv.IsEnabled())
                    {
                        enablePrivilegeToolStripMenuItem.Text = "Disable Privilege";
                    }
                    else
                    {
                        enablePrivilegeToolStripMenuItem.Text = "Enable Privilege";
                    }
                }
            }
        }

        private void enablePrivilegeToolStripMenuItem_Click(object sender, EventArgs e)
        {
            if (listViewPrivs.SelectedItems.Count > 0)
            {
                TokenPrivilege priv = listViewPrivs.SelectedItems[0].Tag as TokenPrivilege;

                try
                {
                    _token.EnablePrivilege(priv, !priv.IsEnabled());
                    UpdatePrivileges();
                }
                catch (Win32Exception ex)
                {
                    MessageBox.Show(this, ex.Message, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
            }
        }
    }
}
