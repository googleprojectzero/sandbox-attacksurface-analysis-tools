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
using System.IO;
using System.Windows.Forms;
using WeifenLuo.WinFormsUI.Docking;

namespace EditSection
{
    public partial class SectionEditorForm : DockContent
    {
        NtMappedSection _map;        
        bool _readOnly;
        NativeMappedFileByteProvider _prov;
        Random _random;

        private SectionEditorForm(NtMappedSection map, bool readOnly)
        {
            _random = new Random();
            _map = map;
            _readOnly = readOnly;
            _prov = new NativeMappedFileByteProvider(_map, _readOnly);            

            InitializeComponent();
            if (_readOnly)
            {
                corruptToolStripMenuItem.Visible = false;
                loadFromFileToolStripMenuItem.Visible = false;
            }

            hexBox.ByteProvider = _prov;

            Disposed += SectionEditorForm_Disposed;
        }

        public SectionEditorForm(NtMappedSection map, NtHandle handle, bool readOnly) 
            : this(map, readOnly)        
        {                           
            TabText = String.Format("Process {0} - Handle {1} {2}", handle.ProcessId, handle.Handle, _readOnly ? "(RO)" : "");            
        }

        public SectionEditorForm(NtMappedSection map, string name, bool readOnly)
            : this(map, readOnly)
        {            
            TabText = String.Format("{0} {1}", name, _readOnly ? "(RO)" : "");
        }

        void SectionEditorForm_Disposed(object sender, EventArgs e)
        {
            _map.Close();
        }

        private void copyToolStripMenuItem_Click(object sender, EventArgs e)
        {
            if (hexBox.CanCopy())
            {
                hexBox.Copy();
            }
        }

        private void saveToFileToolStripMenuItem_Click(object sender, EventArgs e)
        {
            long start = hexBox.SelectionStart;
            long length = hexBox.SelectionLength;

            if (length > 0)
            {
                using (SaveFileDialog dlg = new SaveFileDialog())
                {
                    dlg.Filter = "All Files (*.*)|*.*";

                    if (dlg.ShowDialog(this) == DialogResult.OK)
                    {
                        byte[] data = new byte[length];

                        for (long i = 0; i < length; ++i)
                        {
                            data[i] = _prov.ReadByte(i + start);
                        }

                        try
                        {
                            File.WriteAllBytes(dlg.FileName, data);
                        }
                        catch (IOException ex)
                        {
                            MessageBox.Show(this, ex.Message, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                        }
                    }
                }
            }
        }

        private void loadFromFileToolStripMenuItem_Click(object sender, EventArgs e)
        {
            long start = hexBox.SelectionStart;            

            using (OpenFileDialog dlg = new OpenFileDialog())
            {
                dlg.Filter = "All Files (*.*)|*.*";

                if (dlg.ShowDialog(this) == DialogResult.OK)
                {
                    try
                    {
                        byte[] data = File.ReadAllBytes(dlg.FileName);
                        long totalLength = data.Length;

                        if (start + totalLength > _prov.Length)
                        {
                            totalLength = _prov.Length - start;
                        }

                        for (long i = 0; i < totalLength; ++i)
                        {
                            _prov.WriteByte(start + i, data[i]);
                        }
                    
                        File.WriteAllBytes(dlg.FileName, data);

                        hexBox.Invalidate();
                    }
                    catch (IOException ex)
                    {
                        MessageBox.Show(this, ex.Message, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    }
                }
            }            
        }

        private void corruptToolStripMenuItem_Click(object sender, EventArgs e)
        {
            if (!_readOnly)
            {
                long start = hexBox.SelectionStart;
                long length = hexBox.SelectionLength;

                if (length > 0)
                {
                    using (CorruptSectionForm frm = new CorruptSectionForm())
                    {
                        if (frm.ShowDialog(this) == DialogResult.OK)
                        {
                            ICorruptSection cs = frm.CorruptSectionObject;
                            if (cs != null)
                            {
                                try
                                {
                                    cs.Corrupt(_prov, start, start + length);
                                }
                                catch
                                {
                                }
                            }
                        }
                    }

                    hexBox.Invalidate();
                }
            }
        }

        private void selectAllToolStripMenuItem_Click(object sender, EventArgs e)
        {
            hexBox.SelectAll();
        }
    }
}
