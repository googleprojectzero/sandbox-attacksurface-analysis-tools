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
using System.Windows.Forms;

namespace EditSection
{
    public partial class NamedObjectForm : Form
    {
        string _typename;

        private void UpdateObjectList(string typename, HashSet<string> walked, NtDirectory dir, HashSet<string> names)
        {            
            if (!walked.Add(dir.FullPath))
            {
                return;
            }

            foreach (var entry in dir.Query())
            {
                if(entry.NtTypeName.Equals(typename, StringComparison.OrdinalIgnoreCase))
                {
                    names.Add(entry.FullPath);
                }
                else if (entry.IsDirectory)
                {
                    try
                    {
                        using (NtDirectory subdir = NtDirectory.Open(entry.Name, dir, DirectoryAccessRights.Query))
                        {
                            UpdateObjectList(typename, walked, subdir, names);
                        }
                    }
                    catch (NtException)
                    {
                    }
                }
            }
        }

        private IEnumerable<string> GetObjectList(string typename)
        {            
            HashSet<string> walked = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            HashSet<string> names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);            

            try
            {
                using (NtDirectory dir = NtDirectory.Open(@"\", null, DirectoryAccessRights.Query))
                {
                    UpdateObjectList(typename, walked, dir, names);
                }
            }
            catch (NtException)
            {
            }

            try
            {
                using (NtDirectory dir = NtDirectory.OpenSessionDirectory("BaseNamedObjects"))
                {
                    UpdateObjectList(typename, walked, dir, names);
                }
            }
            catch (NtException)
            {
            }

            List<string> ret = new List<string>(names);

            ret.Sort();

            return ret;
        }

        public NamedObjectForm(string typename)
        {
            InitializeComponent();

            foreach (string name in GetObjectList(typename))
            {
                ListViewItem item = listViewSections.Items.Add(name);

                item.Tag = name;
            }
            Text = "Open Named " + typename;
            _typename = typename;
        }

        private void btnOpen_Click(object sender, EventArgs e)
        {
            if (String.IsNullOrWhiteSpace(txtObjectName.Text))
            {
                MessageBox.Show(this, "Please select a named section", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            else
            {
                string name = txtObjectName.Text;

                try
                {
                    GenericAccessRights access = GenericAccessRights.GenericRead;
                    if (!checkReadOnly.Checked)
                        access |= GenericAccessRights.GenericWrite;
                    ObjectHandle = NtObject.OpenWithType(_typename, name, null, access);
                    ObjectName = name;
                    ReadOnly = checkReadOnly.Checked;
                    DialogResult = DialogResult.OK;
                    Close();
                }
                catch (NtException ex)
                {
                    MessageBox.Show(this, ex.Message, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
            }
        }

        [DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden), Browsable(false)]
        public NtObject ObjectHandle { get; private set; }

        [DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden), Browsable(false)]
        public bool ReadOnly { get; private set; }

        [DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden), Browsable(false)]
        public string ObjectName { get; private set; }

        private void btnCancel_Click(object sender, EventArgs e)
        {
            DialogResult = DialogResult.Cancel;
            Close();
        }

        private void listViewSections_MouseDoubleClick(object sender, MouseEventArgs e)
        {
            btnOpen_Click(sender, e);
        }

        private void listViewSections_SelectedIndexChanged(object sender, EventArgs e)
        {
            if (listViewSections.SelectedItems.Count > 0)
            {
                txtObjectName.Text = listViewSections.SelectedItems[0].Tag.ToString();
            }
        }
    }
}
