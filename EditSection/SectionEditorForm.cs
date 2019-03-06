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

using Be.Windows.Forms;
using NtApiDotNet;
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Windows.Forms;
using WeifenLuo.WinFormsUI.Docking;

namespace EditSection
{
    public partial class SectionEditorForm : DockContent
    {
        private NtMappedSection _map;
        private bool _readOnly;
        private NativeMappedFileByteProvider _prov;
        private Random _random;

        private class FunctionDataInspector : IDataInspector
        {
            private Func<IByteProvider, long, long, string> _func;

            public FunctionDataInspector(string name, Func<IByteProvider, long, long, string> func)
            {
                Name = name;
                _func = func;
            }

            public string Name { get; private set; }

            public string GetValue(IByteProvider provider, long start, long length)
            {
                return _func(provider, start, length);
            }
        }

        private class FixedDataInspector : FunctionDataInspector
        {
            private static string GetFixedValue(IByteProvider provider, long start, long length, int fixed_length, bool reverse, Func<byte[], string> func)
            {
                long max_length = provider.Length - start;
                if (max_length < fixed_length)
                {
                    return string.Empty;
                }
                byte[] ba = new byte[fixed_length];
                if (reverse)
                {
                    for (int i = 0; i < fixed_length; ++i)
                    {
                        ba[fixed_length - i - 1] = provider.ReadByte(i + start);
                    }
                }
                else
                {
                    for (int i = 0; i < fixed_length; ++i)
                    {
                        ba[i] = provider.ReadByte(i + start);
                    }
                }

                return func(ba);
            }

            public FixedDataInspector(string name, int length, bool reverse, Func<byte[], string> func) 
                : base(name, (p, s, l) => GetFixedValue(p, s, l, length, reverse, func))
            {
            }
        }

        private class IntegerDataInspector<T> : FixedDataInspector where T : struct
        {
            private static string FormatInt(byte[] ba, Func<byte[], int, T> func)
            {
                T value = func(ba, 0);
                return $"{value}/0x{value:X}";
            }

            public IntegerDataInspector(bool big_endian, Func<byte[], int, T> func) : 
                base($"{typeof(T).Name} ({(big_endian ? "Big Endian" : "Little Endian")})", 
                    Marshal.SizeOf(typeof(T)), big_endian, ba => FormatInt(ba, func))
            {
            }

            public IntegerDataInspector(Func<byte[], int, T> func) :
                 base(typeof(T).Name, Marshal.SizeOf(typeof(T)), false, ba => FormatInt(ba, func))
            {
            }
        }

        private static IntegerDataInspector<T> CreateIntegerDataInspector<T>(bool big_endian, Func<byte[], int, T> func) where T : struct
        {
            return new IntegerDataInspector<T>(big_endian, func);
        }

        private SectionEditorForm(NtMappedSection map, bool readOnly, long length)
        {
            _random = new Random();
            _map = map;
            _readOnly = readOnly;
            _prov = new NativeMappedFileByteProvider(_map, _readOnly, length);
            _prov.ByteWritten += _prov_ByteWritten;

            InitializeComponent();
            if (_readOnly)
            {
                corruptToolStripMenuItem.Visible = false;
                loadFromFileToolStripMenuItem.Visible = false;
            }

            loadFromFileToolStripMenuItem.Enabled = !_readOnly;
            toolStripButtonLoad.Enabled = !_readOnly;
            hexBox.ByteProvider = _prov;
            InitDataInspectors();
            UpdateDataInspectors();

            Disposed += SectionEditorForm_Disposed;
        }

        private void _prov_ByteWritten(object sender, EventArgs e)
        {
            UpdateDataInspectors();
        }

        private string GetReadOnlyString()
        {
            return $"({_map.Protection.ToString()})";
        }

        public SectionEditorForm(NtMappedSection map, NtHandle handle, bool readOnly, long length) 
            : this(map, readOnly, length)
        {
            TabText = $"Process {handle.ProcessId} - Handle {handle.Handle} {GetReadOnlyString()}";
        }

        public SectionEditorForm(NtMappedSection map, NtHandle handle, bool readOnly)
            : this(map, handle, readOnly, map.LongLength)
        {
        }

        public SectionEditorForm(NtMappedSection map, string name, bool readOnly, long length)
            : this(map, readOnly, length)
        {
            TabText = $"{name} {GetReadOnlyString()}";
            Text = TabText;
        }

        public SectionEditorForm(NtMappedSection map, string name, bool readOnly)
            : this(map, name, readOnly, map.LongLength)
        {
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

        private void AddDataInspector(IDataInspector inspector)
        {
            ListViewItem item = new ListViewItem(inspector.Name);
            item.SubItems.Add(string.Empty);
            item.Tag = inspector;
            listViewInspector.Items.Add(item);
        }

        private void AddIntegerDataInspector<T>(Func<byte[], int, T> func) where T : struct
        {
            AddDataInspector(CreateIntegerDataInspector(false, func));
            AddDataInspector(CreateIntegerDataInspector(true, func));
        }

        private void InitDataInspectors()
        {
            AddDataInspector(new FunctionDataInspector("Position", (p, s, e) => $"{s}/0x{s:X}"));
            AddDataInspector(new FunctionDataInspector("Selection Length", (p, s, l) => $"{l}/0x{l:X}"));
            AddDataInspector(new IntegerDataInspector<byte>((ba, i) => ba[0]));
            AddDataInspector(new IntegerDataInspector<sbyte>((ba, i) => (sbyte)ba[0]));
            AddIntegerDataInspector(BitConverter.ToInt16);
            AddIntegerDataInspector(BitConverter.ToInt32);
            AddIntegerDataInspector(BitConverter.ToInt64);
            AddIntegerDataInspector(BitConverter.ToUInt16);
            AddIntegerDataInspector(BitConverter.ToUInt32);
            AddIntegerDataInspector(BitConverter.ToUInt64);
        }

        private void UpdateDataInspectors()
        {
            long start = hexBox.SelectionStart;
            long length = hexBox.SelectionLength;
            foreach (ListViewItem item in listViewInspector.Items)
            {
                if (item.Tag is IDataInspector inspector)
                {
                    item.SubItems[1].Text = inspector.GetValue(_prov, start, length);
                }
            }
            listViewInspector.AutoResizeColumns(ColumnHeaderAutoResizeStyle.ColumnContent);
        }

        private void SaveSelectionToFile(long start, long length)
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

        private void saveToFileToolStripMenuItem_Click(object sender, EventArgs e)
        {
            long start = hexBox.SelectionStart;
            long length = hexBox.SelectionLength;

            if (length > 0)
            {
                SaveSelectionToFile(start, length);
            }
            else
            {
                MessageBox.Show(this, "Select a part of the section to save", 
                    "Select", MessageBoxButtons.OK, MessageBoxIcon.Exclamation);
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

                        _prov.WriteBytes(start, data);
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

        private void refreshToolStripMenuItem_Click(object sender, EventArgs e)
        {
            hexBox.Refresh();
        }

        private void hexBox_SelectionChanged(object sender, EventArgs e)
        {
            bool sized_selection = hexBox.SelectionLength > 0;
            saveToFileToolStripMenuItem.Enabled = sized_selection;
            toolStripButtonSave.Enabled = sized_selection;
            UpdateDataInspectors();
        }

        private void copyInspectorToolStripMenuItem_Click(object sender, EventArgs e)
        {
            StringBuilder builder = new StringBuilder();
            foreach (ListViewItem item in listViewInspector.SelectedItems)
            {
                builder.AppendLine($"{item.SubItems[0].Text} - {item.SubItems[1].Text}");
            }
            if (builder.Length > 0)
            {
                try
                {
                    Clipboard.SetText(builder.ToString());
                }
                catch
                {
                }
            }
        }
    }
}
