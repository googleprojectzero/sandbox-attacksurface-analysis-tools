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
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Windows.Forms;

namespace TokenViewer
{
    public partial class CreateSandboxTokenForm : Form
    {
        private NtToken _token;
        private NtToken _newtoken;

        [Flags]
        enum SandboxTokenType
        {
            RestrictedOnly = 1,
            LowBoxOnly = 2,
            RestrictedAndLowBox = RestrictedOnly | LowBoxOnly
        }

        [DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden), Browsable(false)]
        public NtToken Token
        {
            get { return _newtoken; }
        }

        private static void PopulateGroupList(ListView listView, IEnumerable<UserGroup> groups)
        {
            foreach (UserGroup group in groups)
            {
                ListViewItem item = new ListViewItem(group.ToString());
                item.SubItems.Add(group.Sid.ToString());
                item.Tag = group;
                listView.Items.Add(item);
            }
        }

        private Sid[] GetGroupFromList(IEnumerable<ListViewItem> items)
        {
            List<Sid> groups = new List<Sid>();
            foreach (ListViewItem item in items)
            {
                groups.Add(((UserGroup)item.Tag).Sid);
            }
            return groups.ToArray();
        }

        private Luid[] GetPrivileges()
        {
            List<Luid> privs = new List<Luid>();
            foreach (ListViewItem item in listViewDeletePrivs.CheckedItems)
            {
                privs.Add(((TokenPrivilege)item.Tag).Luid);
            }
            return privs.ToArray();
        }

        public CreateSandboxTokenForm(NtToken token)
        {
            InitializeComponent();
            _token = token;
            PopulateGroupList(listViewDisableSids, new UserGroup[] { token.User});
            PopulateGroupList(listViewDisableSids, token.Groups.Where(g => !g.DenyOnly));
            foreach (TokenPrivilege priv in token.Privileges)
            {
                ListViewItem item = new ListViewItem(priv.Name);
                item.SubItems.Add(priv.DisplayName);
                item.Tag = priv;
                listViewDeletePrivs.Items.Add(item);
            }
            foreach (object value in Enum.GetValues(typeof(SandboxTokenType)))
            {
                comboBoxSandboxType.Items.Add(value);
            }
            comboBoxSandboxType.SelectedItem = SandboxTokenType.RestrictedOnly;
        }

        private NtToken CreateRestrictedToken(NtToken token)
        {
            FilterTokenFlags flags = FilterTokenFlags.None;
            if (checkBoxDisableMaxPrivs.Checked)
            {
                flags |= FilterTokenFlags.DisableMaxPrivileges;
            }
            if (checkBoxMakeLuaToken.Checked)
            {
                flags |= FilterTokenFlags.LuaToken;
            }
            if (checkBoxSandboxInert.Checked)
            {
                flags |= FilterTokenFlags.SandboxInert;
            }
            if (checkBoxWriteRestricted.Checked)
            {
                flags |= FilterTokenFlags.WriteRestricted;
            }
            
            return token.Filter(flags, GetGroupFromList(listViewDisableSids.CheckedItems.OfType<ListViewItem>()),
                GetPrivileges(), GetGroupFromList(listViewRestrictedSids.Items.OfType<ListViewItem>()));
        }

        private NtToken CreateLowBoxToken(NtToken token)
        {
            Sid package_sid = SandboxAnalysisUtils.TokenUtils.GetPackageSidFromName(textBoxPackageSid.Text);
            if (!NtSecurity.IsPackageSid(package_sid))
            {
                throw new ArgumentException(String.Format("Invalid Package Sid {0}", package_sid));
            }
            
            Sid[] capabilities = GetGroupFromList(listViewCapabilities.Items.OfType<ListViewItem>());
            foreach (Sid cap in capabilities)
            {
                if (!NtSecurity.IsCapabilitySid(cap))
                {
                    throw new ArgumentException(String.Format("Invalid Capability Sid {0}", cap));
                }
            }

            return token.CreateLowBoxToken(package_sid, capabilities,
                new NtObject[0], TokenAccessRights.MaximumAllowed);
        }

        private NtToken CreateToken()
        {
            SandboxTokenType type = GetSelectedTokenType();
            NtToken current_token = _token.Duplicate();

            if ((type & SandboxTokenType.RestrictedOnly) != 0)
            {
                using (NtToken tmp_token = current_token)
                {
                    current_token = CreateRestrictedToken(tmp_token);
                }
            }

            if ((type & SandboxTokenType.LowBoxOnly) != 0)
            {
                using (NtToken tmp_token = current_token)
                {
                    current_token = CreateLowBoxToken(tmp_token);
                }
            }

            return current_token;
        }

        private void btnCreate_Click(object sender, EventArgs e)
        {
            try
            {
                _newtoken = CreateToken();
                DialogResult = DialogResult.OK;
                Close();
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, ex.Message, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void btnAddAllGroups_Click(object sender, EventArgs e)
        {
            PopulateGroupList(listViewRestrictedSids, new UserGroup[] { _token.User});
            PopulateGroupList(listViewRestrictedSids, _token.Groups.Where(g => !g.DenyOnly));
        }

        private static void DoListViewCheck(ListView listView, bool check)
        {            
            foreach (ListViewItem item in listView.Items)
            {
                item.Checked = check;
            }         
        }

        private void checkAllToolStripMenuItem_Click(object sender, EventArgs e)
        {
            DoListViewCheck(listViewDisableSids, true);
        }

        private void uncheckAllToolStripMenuItem_Click(object sender, EventArgs e)
        {
            DoListViewCheck(listViewDisableSids, false);
        }

        private void toolStripMenuItemCheckAllPrivs_Click(object sender, EventArgs e)
        {
            DoListViewCheck(listViewDeletePrivs, true);
        }

        private void toolStripMenuItemUncheckAllPrivs_Click(object sender, EventArgs e)
        {
            DoListViewCheck(listViewDeletePrivs, false);
        }

        private ListView GetListViewOwner(object sender)
        {
            ToolStripItem item = sender as ToolStripItem;
            if (item == null)
            {
                return null;
            }
            ContextMenuStrip menu = item.Owner as ContextMenuStrip;
            if (menu == null)
            {
                return null;
            }
            return menu.SourceControl as ListView;
        }

        private void addSidToolStripMenuItem_Click(object sender, EventArgs e)
        {
            ListView listView = GetListViewOwner(sender);
            if (listView != null)
            {
                using (AddSidForm form = new AddSidForm())
                {
                    if (form.ShowDialog(this) == DialogResult.OK)
                    {
                        UserGroup group = new UserGroup(new Sid(form.Sid), GroupAttributes.None);
                        PopulateGroupList(listView, new UserGroup[] { group });
                    }
                }
            }
        }

        private void deleteSidToolStripMenuItem_Click(object sender, EventArgs e)
        {
            ListView listView = GetListViewOwner(sender);
            if (listView != null)
            {
                List<ListViewItem> selectedItems = listView.SelectedItems.OfType<ListViewItem>().ToList();

                foreach (ListViewItem item in selectedItems)
                {
                    item.Remove();
                }
            }
        }

        private void selectAllToolStripMenuItem_Click(object sender, EventArgs e)
        {
            ListView listView = GetListViewOwner(sender);
            if (listView != null)
            {
                foreach (ListViewItem item in listView.Items)
                {
                    item.Selected = true;
                }
            }
        }

        private void btnCreateNew_Click(object sender, EventArgs e)
        {
            try
            {
                TokenForm.OpenForm(CreateToken(), false);
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, ex.Message, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private static void EnableTabPage(TabPage page, bool enable)
        {
            foreach (Control control in page.Controls)
            {
                control.Enabled = enable;
            }
        }

        private void EnableRestrictedTabPages(bool enable)
        {
            EnableTabPage(tabPageRestrictedSids, enable);
            EnableTabPage(tabPageDisableSids, enable);
            EnableTabPage(tabPageDeletePrivs, enable);
        }

        private void EnableLowBoxTabPages(bool enable)
        {
            EnableTabPage(tabPageAppContainer, enable);
        }

        private SandboxTokenType GetSelectedTokenType()
        {
            if (comboBoxSandboxType.SelectedItem is SandboxTokenType)
            {
                return (SandboxTokenType)comboBoxSandboxType.SelectedItem;
            }
            return SandboxTokenType.RestrictedOnly;
        }
        
        private void comboBoxSandboxType_SelectedIndexChanged(object sender, EventArgs e)
        {
            switch (GetSelectedTokenType())
            {
                case SandboxTokenType.RestrictedOnly:
                    EnableRestrictedTabPages(true);
                    EnableLowBoxTabPages(false);
                    break;
                case SandboxTokenType.LowBoxOnly:
                    EnableRestrictedTabPages(false);
                    EnableLowBoxTabPages(true);
                    break;
                case SandboxTokenType.RestrictedAndLowBox:
                    EnableRestrictedTabPages(true);
                    EnableLowBoxTabPages(true);
                    break;
            }
        }
    }
}
