﻿//  Copyright 2015 Google Inc. All Rights Reserved.
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

using NtCoreLib;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Windows.Forms;

namespace EditSection;

public partial class SelectSectionForm : Form
{
    private static string? _last_filter;

    private NtMappedSection? _mapped_file;
    private NtHandle? _opened_handle;

    private void UpdateProcesses(string nameFilter)
    {
        using var ps = NtProcess.GetProcesses(ProcessAccessRights.DupHandle
            | ProcessAccessRights.QueryLimitedInformation, true).ToDisposableList();
        treeViewProcesses.SuspendLayout();

        try
        {
            treeViewProcesses.Nodes.Clear();
            IEnumerable<NtProcess> ps_list = ps.OrderBy(p => p.ProcessId);
            if (!string.IsNullOrWhiteSpace(nameFilter))
            {
                nameFilter = nameFilter.ToLower();
                ps_list = ps_list.Where(p => p.Name.ToLower().Contains(nameFilter));
            }

            foreach (var p in ps_list)
            {
                TreeNode node = new ProcessTreeNode(p);
                treeViewProcesses.Nodes.Add(node);
            }
        }
        finally
        {
            treeViewProcesses.ResumeLayout();
        }

        _last_filter = nameFilter;
    }

    public SelectSectionForm()
    {
        InitializeComponent();

        if (!string.IsNullOrWhiteSpace(_last_filter))
        {
            textBoxFilter.Text = _last_filter;
        }

        UpdateProcesses(textBoxFilter.Text ?? string.Empty);
    }

    private void treeViewProcesses_BeforeExpand(object sender, TreeViewCancelEventArgs e)
    {
        try
        {
            if (e.Node is ProcessTreeNode node)
            {
                node.PopulateChildren();
            }
        }
        catch
        {
        }
    }

    private void btnOK_Click(object sender, EventArgs e)
    {
        if (OpenMappedFile())
        {
            DialogResult = DialogResult.OK;
            Close();
        }
    }

    private void btnCancel_Click(object sender, EventArgs e)
    {
        DialogResult = DialogResult.Cancel;
        Close();
    }

    private void btnApply_Click(object sender, EventArgs e)
    {
        UpdateProcesses(textBoxFilter.Text);
    }

    private bool OpenMappedFile()
    {
        if (treeViewProcesses.SelectedNode is not SectionTreeNode node)
        {
            MessageBox.Show(this, "Please selection a section to open", "Select Section", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
        else
        {
            try
            {
                _mapped_file = node.OpenMappedFile(!checkBoxOpenReadonly.Checked);
                _opened_handle = node.SectionHandle;
                ReadOnly = checkBoxOpenReadonly.Checked;
                return true;
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, ex.Message, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        return false;
    }

    [DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden), Browsable(false)]
    public NtMappedSection MappedFile => _mapped_file ?? throw new InvalidOperationException();

    [DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden), Browsable(false)]
    public NtHandle OpenedHandle => _opened_handle ?? throw new InvalidOperationException();

    [DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden), Browsable(false)]
    public bool ReadOnly { get; private set; }
}
