//  Copyright 2018 Google Inc. All Rights Reserved.
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

// NOTE: This file is a modified version of NdrParser.cs from OleViewDotNet
// https://github.com/tyranid/oleviewdotnet. It's been relicensed from GPLv3 by
// the original author James Forshaw to be used under the Apache License for this
// project.

using NtApiDotNet.Win32;
using System;
using System.Drawing;
using System.Linq;
using System.Runtime.InteropServices;
using System.Windows.Forms;

namespace NtApiDotNet.Forms
{
    /// <summary>
    /// Control for viewing an ACL.
    /// </summary>
    public partial class AclViewerControl : UserControl
    {
        private Acl _acl;
        private Type _access_type;
        private GenericMapping _mapping;
        private AccessMask _valid_access;
        private Type _current_access_type;
        private bool _read_only_checks;

        /// <summary>
        /// Constructor.
        /// </summary>
        public AclViewerControl()
        {
            InitializeComponent();
        }

        /// <summary>
        /// Set ACL for control.
        /// </summary>
        /// <param name="acl">The ACL to view.</param>
        /// <param name="access_type">The enum type for the view.</param>
        /// <param name="mapping">Generic mapping for the type.</param>
        /// <param name="valid_access">The valid bit mask for access for this type.</param>
        public void SetAcl(Acl acl, Type access_type, GenericMapping mapping, AccessMask valid_access)
        {
            _acl = acl;
            _access_type = access_type;
            _mapping = mapping;
            _valid_access = valid_access;

            if (!acl.HasConditionalAce)
            {
                listViewAcl.Columns.Remove(columnHeaderCondition);
                copyConditionToolStripMenuItem.Visible = false;
            }

            foreach (var ace in acl)
            {
                var item = listViewAcl.Items.Add(ace.Type.ToString());
                item.SubItems.Add(ace.Sid.Name);
                string access;
                if (ace.Type == AceType.MandatoryLabel)
                {
                    access = ace.Mask.ToMandatoryLabelPolicy().ToString();
                }
                else
                {
                    AccessMask mapped_mask = mapping.MapMask(ace.Mask);
                    mapped_mask = mapping.UnmapMask(mapped_mask);
                    access = mapped_mask.ToSpecificAccess(access_type).ToString();
                }

                item.SubItems.Add(access);
                item.SubItems.Add(ace.Flags.ToString());
                if (ace.IsConditionalAce)
                {
                    item.SubItems.Add(ace.Condition);
                }

                item.Tag = ace;

                switch (ace.Type)
                {
                    case AceType.Allowed:
                    case AceType.AllowedCallback:
                    case AceType.AllowedCallbackObject:
                    case AceType.AllowedObject:
                        item.BackColor = Color.LightGreen;
                        break;
                    case AceType.Denied:
                    case AceType.DeniedCallback:
                    case AceType.DeniedCallbackObject:
                    case AceType.DeniedObject:
                        item.BackColor = Color.LightSalmon;
                        break;
                    case AceType.ProcessTrustLabel:
                        item.BackColor = Color.LightSkyBlue;
                        break;
                    case AceType.MandatoryLabel:
                        item.BackColor = Color.LightGoldenrodYellow;
                        break;
                }
            }
            listViewAcl.AutoResizeColumns(ColumnHeaderAutoResizeStyle.ColumnContent);
            listViewAcl.AutoResizeColumns(ColumnHeaderAutoResizeStyle.HeaderSize);
        }

        private Ace GetSelectedAce()
        {
            if (_acl == null)
            {
                return null;
            }
            if (listViewAcl.SelectedItems.Count == 0)
            {
                return null;
            }
            return (Ace)listViewAcl.SelectedItems[0].Tag;
        }

        private void listViewAcl_SelectedIndexChanged(object sender, EventArgs e)
        {
            Ace ace = GetSelectedAce();
            if (ace == null)
            {
                return;
            }
            
            Type access_type = _access_type;
            AccessMask valid_access = _valid_access;
            AccessMask mapped_mask = _mapping.MapMask(ace.Mask) & _valid_access;

            if (ace.Type == AceType.MandatoryLabel)
            {
                mapped_mask = ace.Mask;
                access_type = typeof(MandatoryLabelPolicy);
                valid_access = 0x7;
            }

            if (access_type != _current_access_type)
            {
                _current_access_type = access_type;
                ListViewItem[] items = Win32Utils.GetMaskDictionary(access_type, valid_access).Select(pair =>
                    {
                        ListViewItem item = new ListViewItem(pair.Value);
                        item.SubItems.Add($"0x{pair.Key:X08}");
                        item.Tag = pair.Key;
                        return item;
                    }
                ).ToArray();
                listViewAccess.Items.Clear();
                listViewAccess.Items.AddRange(items);
                listViewAccess.AutoResizeColumns(ColumnHeaderAutoResizeStyle.ColumnContent);
                listViewAccess.AutoResizeColumns(ColumnHeaderAutoResizeStyle.HeaderSize);
            }

            _read_only_checks = false;
            foreach (ListViewItem item in listViewAccess.Items)
            {
                uint mask = (uint)item.Tag;
                item.Checked = (mapped_mask & mask) != 0;
            }
            _read_only_checks = true;
        }

        private void listViewAccess_ItemCheck(object sender, ItemCheckEventArgs e)
        {
            if (_read_only_checks)
            {
                e.NewValue = e.CurrentValue;
            }
        }

        private static void CopyToClipboard(string value)
        {
            try
            {
                Clipboard.SetText(value);
            }
            catch (ExternalException)
            {
            }
        }

        private void copySIDToolStripMenuItem_Click(object sender, EventArgs e)
        {
            Ace ace = GetSelectedAce();
            if (ace == null)
            {
                return;
            }

            CopyToClipboard(ace.Sid.ToString());
        }

        private void contextMenuStripAcl_Opening(object sender, System.ComponentModel.CancelEventArgs e)
        {
            Ace ace = GetSelectedAce();
            bool selected = ace != null;
            copySIDToolStripMenuItem.Enabled = selected;
            copyAccountToolStripMenuItem.Enabled = selected;
            copyConditionToolStripMenuItem.Enabled = selected && ace.IsConditionalAce;
        }

        private void copyAccountToolStripMenuItem_Click(object sender, EventArgs e)
        {
            Ace ace = GetSelectedAce();
            if (ace == null)
            {
                return;
            }

            CopyToClipboard(ace.Sid.Name);
        }

        private void copyConditionToolStripMenuItem_Click(object sender, EventArgs e)
        {
            Ace ace = GetSelectedAce();
            if (ace == null)
            {
                return;
            }
            if (ace.IsConditionalAce)
            {
                CopyToClipboard(ace.Condition);
            }
        }
    }
}
