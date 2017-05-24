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
using System.Threading;
using System.Windows.Forms;
using WeifenLuo.WinFormsUI.Docking;

namespace EditSection
{
    public partial class MainForm : Form
    {
        public MainForm()
        {            
            InitializeComponent();            
        }

        private void exitToolStripMenuItem_Click(object sender, EventArgs e)
        {
            Close();
        }

        private void openSectionToolStripMenuItem_Click(object sender, EventArgs e)
        {
            using (SelectSectionForm frm = new SelectSectionForm())
            {
                if (frm.ShowDialog(this) == DialogResult.OK)
                {                    
                    SectionEditorForm c = new SectionEditorForm(frm.MappedFile, frm.OpenedHandle, frm.ReadOnly);

                    c.Show(dockPanel, DockState.Document);
                }
            }
        }

        private void openNamedSectionToolStripMenuItem_Click(object sender, EventArgs e)
        {
            using (NamedObjectForm frm = new NamedObjectForm("Section"))
            {
                if (frm.ShowDialog(this) == DialogResult.OK)
                {
                    using (NtSection handle = (NtSection)frm.ObjectHandle)
                    {
                        NtMappedSection mapped_file = handle.Map(frm.ReadOnly ? MemoryAllocationProtect.ReadOnly : MemoryAllocationProtect.ReadWrite);
                        SectionEditorForm c = new SectionEditorForm(mapped_file, frm.ObjectName, frm.ReadOnly);

                        c.Show(dockPanel, DockState.Document);
                    }
                }
            }
        }

        private void setNamedEventToolStripMenuItem_Click(object sender, EventArgs e)
        {
            using (NamedObjectForm frm = new NamedObjectForm("Event"))
            {
                if (frm.ShowDialog(this) == DialogResult.OK)
                {
                    using(NtEvent handle = (NtEvent)frm.ObjectHandle)
                    {
                        try
                        {
                            handle.Set();
                        }
                        catch (Exception ex)
                        {
                            MessageBox.Show(this, ex.Message, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                        }
                    }
                }
            }
        }
    }
}
