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
using System.Windows.Forms;

namespace EditSection
{
    public partial class NamedSectionForm : Form
    {
        private void UpdateSectionList(HashSet<string> walked, ObjectDirectory dir, HashSet<string> names)
        {            
            if (walked.Contains(dir.FullPath.ToLower()))
            {
                return;
            }

            walked.Add(dir.FullPath.ToLower());

            try
            {
                foreach (ObjectDirectoryEntry entry in dir.Entries)
                {
                    try
                    {  
                        if(entry.TypeName.Equals("Section", StringComparison.OrdinalIgnoreCase))
                        {
                            names.Add(entry.FullPath);
                        }
                        else if (entry.IsDirectory)
                        {
                            UpdateSectionList(walked, ObjectNamespace.OpenDirectory(entry.FullPath), names);
                        }
                    }
                    catch
                    {                        
                    }
                }             
            }
            catch
            {                
            }        
        }

        private IEnumerable<string> GetSectionList()
        {            
            HashSet<string> walked = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            HashSet<string> names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            

            try
            {
                ObjectDirectory basedir = ObjectNamespace.OpenDirectory("\\");
                UpdateSectionList(walked, basedir, names);
            }
            catch (Win32Exception)
            {
            }

            try
            {
                ObjectDirectory sessiondir = ObjectNamespace.OpenSessionDirectory();
                UpdateSectionList(walked, sessiondir, names);
            }
            catch (Win32Exception)
            {
            }

            List<string> ret = new List<string>(names);

            ret.Sort();

            return ret;
        }

        public NamedSectionForm()
        {
            InitializeComponent();

            foreach (string name in GetSectionList())
            {
                ListViewItem item = listViewSections.Items.Add(name);

                item.Tag = name;
            }
        }

        private void btnOpen_Click(object sender, EventArgs e)
        {
            if (listViewSections.SelectedItems.Count < 1)
            {
                MessageBox.Show(this, "Please select a named section", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            else
            {
                string name = listViewSections.SelectedItems[0].Tag.ToString();

                try
                {
                    MappedFile = NativeBridge.MapFile(name, !checkReadOnly.Checked);
                    SectionName = name;
                    ReadOnly = checkReadOnly.Checked;
                    DialogResult = DialogResult.OK;
                    Close();
                }
                catch (Win32Exception ex)
                {
                    MessageBox.Show(this, ex.Message, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
            }
        }

        [DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden), Browsable(false)]
        public NativeMappedFile MappedFile { get; private set; }

        [DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden), Browsable(false)]
        public bool ReadOnly { get; private set; }

        [DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden), Browsable(false)]
        public string SectionName { get; private set; }

        private void btnCancel_Click(object sender, EventArgs e)
        {
            DialogResult = DialogResult.Cancel;
            Close();
        }

        private void listViewSections_MouseDoubleClick(object sender, MouseEventArgs e)
        {
            btnOpen_Click(sender, e);
        }
    }
}
