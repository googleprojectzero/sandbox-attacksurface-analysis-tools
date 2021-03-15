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
using System.Collections.Generic;
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
        private bool _is_container;
        private Type _current_access_type;
        private bool _generic_access_mask;
        private bool _read_only_checks;
        private bool _sdk_names;

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
            SetAcl(acl, access_type, mapping, valid_access, false);
        }

        /// <summary>
        /// Set ACL for control.
        /// </summary>
        /// <param name="acl">The ACL to view.</param>
        /// <param name="access_type">The enum type for the view.</param>
        /// <param name="mapping">Generic mapping for the type.</param>
        /// <param name="valid_access">The valid bit mask for access for this type.</param>
        /// <param name="is_container">True to indicate this object is a container.</param>
        /// <param name="sdk_names">Show the ACEs using SDK style names.</param>
        public void SetAcl(Acl acl, Type access_type, GenericMapping mapping, AccessMask valid_access, bool is_container, bool sdk_names)
        {
            _acl = acl;
            _access_type = access_type;
            _mapping = mapping;
            _valid_access = valid_access;
            _is_container = is_container;
            _sdk_names = sdk_names;
            showSDKNamesToolStripMenuItem.Checked = sdk_names;

            bool has_conditional_ace = false;
            bool has_inherited_object_ace = false;
            bool has_object_ace = false;

            List<string> flags = new List<string>();
            if (acl.Defaulted)
            {
                flags.Add("Defaulted");
            }
            if (acl.Protected)
            {
                flags.Add("Protected");
            }
            if (acl.AutoInherited)
            {
                flags.Add("AutoInherited");
            }
            if (acl.AutoInheritReq)
            {
                flags.Add("AutoInheritReq");
            }

            if (flags.Count > 0)
            {
                lblFlags.Text = $"Flags: {string.Join(", ", flags)}";
            }
            else
            {
                lblFlags.Text = "Flags: None";
            }

            if (acl.NullAcl)
            {
                lblFlags.Text += Environment.NewLine + "NULL ACL";
                listViewAcl.Visible = false;
                listViewAccess.Visible = false;
                groupBoxAclEntries.Visible = false;
                groupBoxAccess.Visible = false;
                return;
            }

            listViewAcl.Items.Clear();
            listViewAcl.Visible = true;
            listViewAccess.Visible = true;
            listViewAccess.Items.Clear();
            _current_access_type = null;
            groupBoxAclEntries.Visible = true;
            groupBoxAccess.Visible = true;

            foreach (var ace in acl)
            {
                if (ace.IsConditionalAce)
                {
                    has_conditional_ace = true;
                }
                if (ace.IsObjectAce)
                {
                    if (ace.ObjectType.HasValue)
                    {
                        has_object_ace = true;
                    }
                    if (ace.InheritedObjectType.HasValue)
                    {
                        has_inherited_object_ace = true;
                    }
                }
            }

            if (!has_conditional_ace)
            {
                listViewAcl.Columns.Remove(columnHeaderCondition);
                copyConditionToolStripMenuItem.Visible = false;
            }

            if (!has_object_ace)
            {
                listViewAcl.Columns.Remove(columnHeaderObject);
            }

            if (!has_inherited_object_ace)
            {
                listViewAcl.Columns.Remove(columnHeaderInheritedObject);
            }

            foreach (var ace in acl)
            {
                var item = listViewAcl.Items.Add(sdk_names ? NtSecurity.AceTypeToSDKName(ace.Type) : ace.Type.ToString());
                item.SubItems.Add(ace.Sid.Name);
                string access;
                if (ace.Type == AceType.MandatoryLabel)
                {
                    access = NtSecurity.AccessMaskToString(ace.Mask.ToMandatoryLabelPolicy(), sdk_names);
                }
                else if (ace.Flags.HasFlag(AceFlags.InheritOnly))
                {
                    access = NtSecurity.AccessMaskToString(ace.Mask.ToSpecificAccess(access_type), sdk_names);
                }
                else
                {
                    AccessMask mapped_mask = mapping.MapMask(ace.Mask);
                    mapped_mask = mapping.UnmapMask(mapped_mask);
                    access = NtSecurity.AccessMaskToString(mapped_mask.ToSpecificAccess(access_type), sdk_names);
                }

                item.SubItems.Add(access);
                item.SubItems.Add(sdk_names ? NtSecurity.AceFlagsToSDKName(ace.Flags) : ace.Flags.ToString());
                if (has_conditional_ace)
                {
                    item.SubItems.Add(ace.Condition);
                }

                if (has_object_ace)
                {
                    item.SubItems.Add(ace.ObjectType?.ToString() ?? string.Empty);
                }

                if (has_inherited_object_ace)
                {
                    item.SubItems.Add(ace.InheritedObjectType?.ToString() ?? string.Empty);
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
                    case AceType.Audit:
                    case AceType.AuditCallback:
                    case AceType.AuditCallbackObject:
                    case AceType.AuditObject:
                        item.BackColor = Color.LightCoral;
                        break;
                }
            }
            listViewAcl.AutoResizeColumns(ColumnHeaderAutoResizeStyle.ColumnContent);
            listViewAcl.AutoResizeColumns(ColumnHeaderAutoResizeStyle.HeaderSize);
        }

        /// <summary>
        /// Set ACL for control.
        /// </summary>
        /// <param name="acl">The ACL to view.</param>
        /// <param name="access_type">The enum type for the view.</param>
        /// <param name="mapping">Generic mapping for the type.</param>
        /// <param name="valid_access">The valid bit mask for access for this type.</param>
        /// <param name="is_container">True to indicate this object is a container.</param>
        public void SetAcl(Acl acl, Type access_type, GenericMapping mapping, AccessMask valid_access, bool is_container)
        {
            SetAcl(acl, access_type, mapping, valid_access, is_container, false);
        }

        /// <summary>
        /// Reset the existing ACL for the control.
        /// </summary>
        /// <param name="sdk_names">Show the ACEs using SDK style names.</param>
        public void ResetAcl(bool sdk_names)
        {
            SetAcl(_acl, _access_type, _mapping, _valid_access, _is_container, sdk_names);
        }

        /// <summary>
        /// Query whether SDK names are being shown in the control.
        /// </summary>
        public bool ShowSDKName => showSDKNamesToolStripMenuItem.Checked;

        /// <summary>
        /// Event for when SDK name property is changed.
        /// </summary>
        public EventHandler ShowSDKNameChanged;

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
            bool generic_access_mask = false;

            if (ace.Type == AceType.MandatoryLabel)
            {
                mapped_mask = ace.Mask;
                access_type = typeof(MandatoryLabelPolicy);
                valid_access = 0x7;
            }
            else if (ace.Flags.HasFlag(AceFlags.InheritOnly))
            {
                mapped_mask = ace.Mask;
                generic_access_mask = true;
                valid_access = valid_access 
                    | GenericAccessRights.GenericRead 
                    | GenericAccessRights.GenericWrite 
                    | GenericAccessRights.GenericExecute 
                    | GenericAccessRights.GenericAll;
            }

            if (access_type != _current_access_type || generic_access_mask != _generic_access_mask)
            {
                _generic_access_mask = generic_access_mask;
                _current_access_type = access_type;
                var masks = Win32Utils.GetMaskDictionary(access_type, valid_access, _sdk_names);
                var ordered = generic_access_mask ? masks.OrderByDescending(p => p.Key) : masks.OrderBy(p => p.Key);
                ListViewItem[] items = ordered.Select(pair =>
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

        private void copyACESDDLToolStripMenuItem_Click(object sender, EventArgs e)
        {
            Ace ace = GetSelectedAce();
            if (ace == null)
            {
                return;
            }

            SecurityDescriptor sd = new SecurityDescriptor
            {
                Dacl = new Acl() { ace }
            };

            // Copy and remove the DACL prefix.
            CopyToClipboard(sd.ToSddl().Substring(2));
        }

        private void showSDKNamesToolStripMenuItem_Click(object sender, EventArgs e)
        {
            ResetAcl(!showSDKNamesToolStripMenuItem.Checked);
            ShowSDKNameChanged?.Invoke(this, new EventArgs());
        }
    }
}
