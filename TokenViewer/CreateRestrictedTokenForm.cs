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

using NtApiDotNet;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Windows.Forms;

namespace TokenViewer
{
    public partial class CreateRestrictedTokenForm : Form
    {
        private NtToken _token;
        private NtToken _newtoken;

        [DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden), Browsable(false)]
        public NtToken RestrictedToken
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

        public CreateRestrictedTokenForm(NtToken token)
        {
            InitializeComponent();
            _token = token;
            PopulateGroupList(listViewDisableSids, new UserGroup[] { token.GetUser() });
            PopulateGroupList(listViewDisableSids, token.GetGroups().Where(g => !g.IsDenyOnly));
            foreach (TokenPrivilege priv in token.GetPrivileges())
            {
                ListViewItem item = new ListViewItem(priv.GetName());
                item.SubItems.Add(priv.GetDisplayName());
                item.Tag = priv;
                listViewDeletePrivs.Items.Add(item);
            }
        }

        private NtToken CreateRestrictedToken()
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
            
            return _token.Filter(flags, GetGroupFromList(listViewDisableSids.CheckedItems.OfType<ListViewItem>()),
                GetPrivileges(), GetGroupFromList(listViewRestrictedSids.Items.OfType<ListViewItem>()));
        }

        private void btnCreate_Click(object sender, EventArgs e)
        {
            try
            {
                _newtoken = CreateRestrictedToken();
                DialogResult = DialogResult.OK;
                Close();
            }
            catch (Win32Exception ex)
            {
                MessageBox.Show(this, ex.Message, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void btnAddAllGroups_Click(object sender, EventArgs e)
        {
            PopulateGroupList(listViewRestrictedSids, new UserGroup[] { _token.GetUser() });
            PopulateGroupList(listViewRestrictedSids, _token.GetGroups().Where(g => !g.IsDenyOnly));
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

        private void addSidToolStripMenuItem_Click(object sender, EventArgs e)
        {
            using (AddSidForm form = new AddSidForm())
            {
                if (form.ShowDialog(this) == DialogResult.OK)
                {
                    UserGroup group = new UserGroup(new Sid(form.Sid), GroupAttributes.None);
                    PopulateGroupList(listViewRestrictedSids, new UserGroup[] { group });
                }
            }
        }

        private void deleteSidToolStripMenuItem_Click(object sender, EventArgs e)
        {
            List<ListViewItem> selectedItems = listViewRestrictedSids.SelectedItems.OfType<ListViewItem>().ToList();

            foreach (ListViewItem item in selectedItems)
            {
                item.Remove();
            }
        }

        private void selectAllToolStripMenuItem_Click(object sender, EventArgs e)
        {
            foreach (ListViewItem item in listViewRestrictedSids.Items)
            {
                item.Selected = true;
            }
        }

        private void btnCreateNew_Click(object sender, EventArgs e)
        {
            try
            {
                TokenForm.OpenForm(CreateRestrictedToken(), false);
            }
            catch (Win32Exception ex)
            {
                MessageBox.Show(this, ex.Message, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }
    }
}
