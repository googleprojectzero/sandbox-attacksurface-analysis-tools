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

using System.Drawing;
using System.Windows.Forms;

namespace NtApiDotNet.Forms
{
    /// <summary>
    /// Control for viewing an ACL.
    /// </summary>
    public partial class AclViewerControl : UserControl
    {
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
        /// <param name="type">The underlying NT type.</param>
        public void SetAcl(Acl acl, NtType type)
        {
            if (!acl.HasConditionalAce)
            {
                listViewAcl.Columns.Remove(columnHeaderCondition);
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
                    GenericMapping mapping = type.GenericMapping;
                    AccessMask mapped_mask = mapping.UnmapMask(mapping.MapMask(ace.Mask));
                    access = mapped_mask.ToSpecificAccess(type.AccessRightsType).ToString();
                }

                item.SubItems.Add(access);
                if (ace.IsConditionalAce)
                {
                    item.SubItems.Add(ace.Condition);
                }

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
    }
}
