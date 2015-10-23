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

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO.Pipes;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Linq;
using TokenLibrary;
using HandleUtils;

namespace TokenViewer
{
    public partial class MainForm : Form
    {
        private void AddProcessNode(ProcessEntry entry, bool hideUnrestricted)
        {
            try
            {
                UserToken token = entry.Token;
                TreeNode node = new TreeNode(String.Format("Pid: {0} - Name: {1} (User:{2}, IL: {3}, R: {4}, AC: {5})",
                   entry.Pid, entry.Name, token.GetUser().GetName(), token.GetTokenIntegrityLevel(),
                   token.IsRestricted(), token.IsAppContainer()));
                node.Tag = entry;

                treeViewProcesses.Nodes.Add(node);
            }
            catch (Win32Exception)
            {
                // Do nothing
            }
        }

        private void RefreshProcessList(string filter, bool hideUnrestricted)
        {
            List<ProcessEntry> processes = ProcessEntry.GetProcesses();
            processes.Sort((a, b) => a.Pid - b.Pid);

            IEnumerable<ProcessEntry> filtered = processes.Where(p => p.Token != null);

            if(!String.IsNullOrWhiteSpace(filter))
            {
                filter = filter.ToLower();
                filtered = filtered.Where(p => p.Name.ToLower().Contains(filter));
            }

            if(hideUnrestricted)
            {
                filtered = filtered.Where(p => p.Token.IsRestricted() || p.Token.IsAppContainer() || p.Token.GetTokenIntegrityLevel() < TokenIntegrityLevel.Medium);
            }

            treeViewProcesses.Nodes.Clear();
            foreach (ProcessEntry entry in filtered)
            {                
                AddProcessNode(entry, hideUnrestricted);
            }
        }

        public MainForm()
        {
            InitializeComponent();

            RefreshProcessList(null, false);

            comboBoxS4ULogonType.Items.Add(LogonType.Batch);
            comboBoxS4ULogonType.Items.Add(LogonType.Interactive);
            comboBoxS4ULogonType.Items.Add(LogonType.Network);
            comboBoxS4ULogonType.Items.Add(LogonType.NetworkCleartext);
            comboBoxS4ULogonType.Items.Add(LogonType.NewCredentials);
            comboBoxS4ULogonType.Items.Add(LogonType.Service);

            comboBoxS4ULogonType.SelectedItem = LogonType.Network;
        }

        private void btnTestS4U_Click(object sender, EventArgs e)
        {
            try
            {
                LogonType logonType = (LogonType)comboBoxS4ULogonType.SelectedItem;

                if (radioLUNormal.Checked)
                {
                    using (UserToken token = TokenUtils.GetLogonUserToken(txtS4UUserName.Text, txtS4URealm.Text, txtLUPassword.Text, null, logonType))
                    {
                        TokenForm.OpenForm(this, token, true);
                    }
                }
                else
                {
                    using (UserToken token = TokenUtils.GetLogonS4UToken(txtS4UUserName.Text, txtS4URealm.Text, logonType))
                    {
                        TokenForm.OpenForm(this, token, true);
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
                ProcessEntry process = selectedNode.Tag as ProcessEntry;
                HandleEntry handle = selectedNode.Tag as HandleEntry;
                if (process != null)
                {
                    TokenForm.OpenForm(this, process.Token, true);
                }
                else if (handle != null)
                {
                    try
                    {
                        TokenForm.OpenForm(this, new UserToken(NativeBridge.DuplicateHandleFromProcess(handle,
                            (uint)(TokenAccessRights.Query | TokenAccessRights.QuerySource), 0)), false);
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
                TokenForm.OpenForm(this, TokenUtils.GetAnonymousToken(), false);
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
                TokenForm.OpenForm(this, TokenUtils.GetLogonUserToken(name, "NT AUTHORITY", null, null, LogonType.Service), false);
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
                TokenForm.OpenForm(this, TokenUtils.GetTokenFromBits(), false);
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

                    UserToken token = null;

                    if (pipe.IsConnected)
                    {
                        pipe.RunAsClient(() => token = TokenUtils.GetTokenFromThread());
                        pipe.Disconnect();
                    }

                    if (token != null)
                    {
                        TokenForm.OpenForm(this, token, false);
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
                TokenForm.OpenForm(this, TokenUtils.GetTokenFromCurrentProcess(), false);
            }
            catch (Win32Exception ex)
            {
                MessageBox.Show(this, ex.Message, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void btnClipboardToken_Click(object sender, EventArgs e)
        {
            try
            {
                TokenForm.OpenForm(this, TokenUtils.GetTokenFromClipboard(), false);
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
            if (node != null && node.Tag is ProcessEntry)
            {
                ProcessEntry entry = (ProcessEntry)node.Tag;
                IEnumerable<HandleEntry> handles = NativeBridge.GetHandlesForPid(entry.Pid, false);
                node.Nodes.Clear();
                foreach (HandleEntry handle in handles)
                {
                    if (handle.TypeName == "Token")
                    {
                        TreeNode token_node = new TreeNode(String.Format("Handle: 0x{0:X}", handle.Handle.ToInt32()));
                        token_node.Tag = handle;
                        node.Nodes.Add(token_node);
                    }
                }
                node.ExpandAll();
            }
        }
    }
}
