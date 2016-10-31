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
using NtApiDotNet;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO.Pipes;
using System.Linq;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace TokenViewer
{
    public partial class MainForm : Form
    {
        private void AddProcessNode(NtProcess entry)
        {
            try
            {
                using (NtToken token = entry.OpenToken())
                {
                    TreeNode node = new TreeNode(String.Format("Pid: {0} - Name: {1} (User:{2}, IL: {3}, R: {4}, AC: {5})",
                       entry.ProcessId, entry.Name, token.User, token.IntegrityLevel,
                       token.Restricted, token.AppContainer));
                    node.Tag = entry.Duplicate();
                    treeViewProcesses.Nodes.Add(node);
                }
            }
            catch
            {
                // Do nothing
            }
        }

        private void AddThreads(NtProcess entry)
        {
            using (DisposableList<NtThread> threads = new DisposableList<NtThread>(entry.GetThreads(ThreadAccessRights.QueryInformation)))
            {
                foreach (NtThread thread in threads)
                {
                    try
                    {
                        using (NtToken token = thread.OpenToken())
                        {
                            if (token != null)
                            {
                                ListViewItem item = new ListViewItem(String.Format("{0} - {1}", entry.ProcessId, entry.Name));
                                item.SubItems.Add(thread.ThreadId.ToString());
                                item.SubItems.Add(token.User.ToString());
                                item.SubItems.Add(token.ImpersonationLevel.ToString());
                                item.Tag = thread.Duplicate();
                                listViewThreads.Items.Add(item);
                            }
                        }
                    }
                    catch (NtException)
                    {
                    }
                }
            }
        }

        private static NtToken GetToken(NtProcess process)
        {
            try
            {
                return process.OpenToken();
            }
            catch (NtException)
            {
                return null;
            }
        }

        private static NtToken GetToken(NtThread thread)
        {
            try
            {
                return thread.OpenToken();
            }
            catch (NtException)
            {
                return null;
            }
        }

        private static NtToken GetProcessToken(NtThread thread)
        {
            try
            {
                return NtToken.OpenProcessToken(thread.ProcessId);
            }
            catch (NtException)
            {
                return null;
            }
        }

        private static bool IsRestrictedToken(NtProcess process)
        {
            NtToken token = null;
            try
            {
                token = GetToken(process);
                if (token == null)
                {
                    return false;
                }
                return token.Restricted|| token.AppContainer|| token.IntegrityLevel< TokenIntegrityLevel.Medium;
            }
            catch (NtException)
            {
                return false;
            }
            finally
            {
                if (token != null)
                {
                    token.Close();
                }
            }
        }

        private void ClearList(ListView view)
        {
            foreach (ListViewItem item in view.Items)
            {
                IDisposable disp = item.Tag as IDisposable;
                if (disp != null)
                {
                    disp.Dispose();
                }
            }
            view.Items.Clear();
        }

        private void ClearTree(TreeView view)
        {
            foreach (TreeNode node in view.Nodes)
            {
                IDisposable disp = node.Tag as IDisposable;
                if (disp != null)
                {
                    disp.Dispose();
                }
            }
            view.Nodes.Clear();
        }

        private void RefreshProcessList(string filter, bool hideUnrestricted)
        {
            using (var processes = new DisposableList<NtProcess>(NtProcess.GetProcesses(ProcessAccessRights.QueryInformation)))
            {
                processes.Sort((a, b) => a.ProcessId- b.ProcessId);

                IEnumerable<NtProcess> filtered = processes.Where(p => GetToken(p) != null);

                if (!String.IsNullOrWhiteSpace(filter))
                {
                    filter = filter.ToLower();
                    filtered = filtered.Where(p => p.FullPath.ToLower().Contains(filter));
                }

                if (hideUnrestricted)
                {
                    filtered = filtered.Where(p => IsRestrictedToken(p));
                }

                ClearTree(treeViewProcesses);
                ClearList(listViewThreads);
                foreach (NtProcess entry in filtered)
                {
                    AddProcessNode(entry);
                    AddThreads(entry);
                }
                listViewThreads.AutoResizeColumns(ColumnHeaderAutoResizeStyle.ColumnContent);
                listViewThreads.AutoResizeColumns(ColumnHeaderAutoResizeStyle.HeaderSize);
            }
        }

        private void RefreshSessionList()
        {
            using (DisposableList<NtToken> tokens = new DisposableList<NtToken>(TokenUtils.GetSessionTokens()))
            {
                ClearList(listViewSessions);
                foreach (NtToken token in tokens)
                {
                    ListViewItem item = new ListViewItem(token.SessionId.ToString());
                    item.SubItems.Add(token.User.ToString());
                    item.Tag = token.Duplicate();
                    listViewSessions.Items.Add(item);
                }
            }
        }

        public MainForm()
        {
            InitializeComponent();

            RefreshProcessList(null, false);
            RefreshSessionList();
            comboBoxS4ULogonType.Items.Add(SecurityLogonType.Batch);
            comboBoxS4ULogonType.Items.Add(SecurityLogonType.Interactive);
            comboBoxS4ULogonType.Items.Add(SecurityLogonType.Network);
            comboBoxS4ULogonType.Items.Add(SecurityLogonType.NetworkCleartext);
            comboBoxS4ULogonType.Items.Add(SecurityLogonType.NewCredentials);
            comboBoxS4ULogonType.Items.Add(SecurityLogonType.Service);
            comboBoxS4ULogonType.SelectedItem = SecurityLogonType.Network;
            TokenForm.RegisterMainForm(this);            
        }

        private void btnTestS4U_Click(object sender, EventArgs e)
        {
            try
            {
                SecurityLogonType logonType = (SecurityLogonType)comboBoxS4ULogonType.SelectedItem;

                if (radioLUNormal.Checked)
                {
                    using (NtToken token = TokenUtils.GetLogonUserToken(txtS4UUserName.Text, txtS4URealm.Text, txtLUPassword.Text, logonType))
                    {
                        TokenForm.OpenForm(token, true);
                    }
                }
                else
                {
                    using (NtToken token = TokenUtils.GetLogonS4UToken(txtS4UUserName.Text, txtS4URealm.Text, logonType))
                    {
                        TokenForm.OpenForm(token, true);
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, ex.Message, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void MainForm_Load(object sender, EventArgs e)
        {
            txtS4UUserName.Text = Environment.UserName;
            txtS4URealm.Text = Environment.UserDomainName;
        }

        private void openTokenToolStripMenuItem_Click(object sender, EventArgs e)
        {
            TreeNode selectedNode = treeViewProcesses.SelectedNode;

            if (selectedNode != null)
            {
                NtProcess process = selectedNode.Tag as NtProcess;
                NtHandle handle = selectedNode.Tag as NtHandle;
                if (process != null)
                {
                    NtToken token = GetToken(process);
                    if (token != null)
                    {
                        TokenForm.OpenForm(token, true);
                    }
                }
                else if (handle != null)
                {
                    try
                    {
                        TokenForm.OpenForm(NtToken.DuplicateFrom(handle.ProcessId, new IntPtr(handle.Handle), TokenAccessRights.Query | TokenAccessRights.QuerySource), false);
                    }
                    catch (Exception ex)
                    {
                        MessageBox.Show(this, ex.Message, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    }
                }
            }
        }

        private void treeViewProcesses_MouseDown(object sender, MouseEventArgs e)
        {
            if (e.Button == System.Windows.Forms.MouseButtons.Right)
            {
                treeViewProcesses.SelectedNode = treeViewProcesses.GetNodeAt(e.Location);
            }
        }

        private void btnCreateAnonymous_Click(object sender, EventArgs e)
        {
            try
            {
                TokenForm.OpenForm(TokenUtils.GetAnonymousToken(), false);
            }
            catch (Win32Exception ex)
            {
                MessageBox.Show(this, ex.Message, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void GetServiceToken(string name)
        {
            try
            {
                TokenForm.OpenForm(TokenUtils.GetLogonUserToken(name, "NT AUTHORITY", null, SecurityLogonType.Service), false);
            }
            catch (Win32Exception ex)
            {
                MessageBox.Show(this, ex.Message, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void btnCreateLocalService_Click(object sender, EventArgs e)
        {
            GetServiceToken("LocalService");
        }

        private void btnCreateNetworkService_Click(object sender, EventArgs e)
        {
            GetServiceToken("NetworkService");
        }

        private void btnCreateSystem_Click(object sender, EventArgs e)
        {
            GetServiceToken("SYSTEM");
        }

        private void radioLUS4U_CheckedChanged(object sender, EventArgs e)
        {
            txtLUPassword.Enabled = !radioLUS4U.Checked;
        }

        private void btnCreateFromBits_Click(object sender, EventArgs e)
        {
            try
            {
                // TODO: Fix
                //TokenForm.OpenForm(TokenUtils3.GetTokenFromBits(), false);
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, ex.Message, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private async void btnStartServer_Click(object sender, EventArgs e)
        {
            try
            {
                btnStartServer.Enabled = false;

                using (NamedPipeServerStream pipe = new NamedPipeServerStream(txtPipeName.Text,
                    PipeDirection.In, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous))
                {
                    await Task.Factory.FromAsync(pipe.BeginWaitForConnection,
                        pipe.EndWaitForConnection, null);

                    NtToken token = null;

                    if (pipe.IsConnected)
                    {
                        pipe.RunAsClient(() => token = NtToken.OpenThreadToken());
                        pipe.Disconnect();
                    }

                    if (token != null)
                    {
                        TokenForm.OpenForm(token, false);
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, ex.Message, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            finally
            {
                btnStartServer.Enabled = true;
            }
        }

        private void btnPipeConnect_Click(object sender, EventArgs e)
        {
            try
            {
                using (NamedPipeClientStream pipe = new NamedPipeClientStream("localhost", txtPipeName.Text, PipeDirection.Out))
                {
                    pipe.Connect(1000);                    
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, ex.Message, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }            
        }

        private void btnCurrentProcess_Click(object sender, EventArgs e)
        {
            try
            {
                TokenForm.OpenForm(NtToken.OpenProcessToken(), false);
            }
            catch (NtException ex)
            {
                MessageBox.Show(this, ex.Message, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void btnClipboardToken_Click(object sender, EventArgs e)
        {
            try
            {
                TokenForm.OpenForm(TokenUtils.GetTokenFromClipboard(), false);
            }
            catch (Win32Exception ex)
            {
                MessageBox.Show(this, ex.Message, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void refreshToolStripMenuItem_Click(object sender, EventArgs e)
        {
            RefreshProcessList(txtFilter.Text, checkBoxUnrestricted.Checked);
        }

        private void btnFilter_Click(object sender, EventArgs e)
        {
            RefreshProcessList(txtFilter.Text, checkBoxUnrestricted.Checked);
        }

        private void refreshTokenHandlesToolStripMenuItem_Click(object sender, EventArgs e)
        {
            TreeNode node = treeViewProcesses.SelectedNode;
            if (node != null && node.Tag is NtProcess)
            {
                NtProcess entry = (NtProcess)node.Tag;
                IEnumerable<NtHandle> handles = NtSystemInfo.GetHandles(entry.ProcessId, false);
                node.Nodes.Clear();
                foreach (NtHandle handle in handles)
                {
                    if (handle.ObjectType.Equals("Token", StringComparison.OrdinalIgnoreCase))
                    {
                        TreeNode token_node = new TreeNode(String.Format("Handle: 0x{0:X}", handle.Handle));
                        token_node.Tag = handle;
                        node.Nodes.Add(token_node);
                    }
                }
                node.ExpandAll();
            }
        }

        private void toolStripMenuItemOpenThreadToken_Click(object sender, EventArgs e)
        {
            if (listViewThreads.SelectedItems.Count > 0)
            {                
                NtThread thread = listViewThreads.SelectedItems[0].Tag as NtThread;
                if(thread != null)
                {
                    NtToken token = GetToken(thread);
                    if (token != null)
                    {
                        TokenForm.OpenForm(token, false);
                    }
                }
            }
        }

        private void openProcessTokenToolStripMenuItem_Click(object sender, EventArgs e)
        {
            if (listViewThreads.SelectedItems.Count > 0)
            {
                NtThread thread = listViewThreads.SelectedItems[0].Tag as NtThread;
                if (thread != null)
                {
                    TokenForm.OpenForm(GetProcessToken(thread), false);
                }
            }
        }

        private void refreshSessionsToolStripMenuItem_Click(object sender, EventArgs e)
        {
            RefreshSessionList();
        }

        private void openSessionTokenToolStripMenuItem_Click(object sender, EventArgs e)
        {
            if (listViewSessions.SelectedItems.Count > 0)
            {
                NtToken token = listViewSessions.SelectedItems[0].Tag as NtToken;
                if (token != null)
                {
                    TokenForm.OpenForm(token, true);
                }
            }
        }
    }
}
