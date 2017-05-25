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
using System.Collections.Generic;
using System.Diagnostics;
using System.IO.Pipes;
using System.Linq;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace TokenViewer
{
    public partial class MainForm : Form
    {
        private static void ResizeColumns(ListView view)
        {
            view.AutoResizeColumns(ColumnHeaderAutoResizeStyle.ColumnContent);
            view.AutoResizeColumns(ColumnHeaderAutoResizeStyle.HeaderSize);
        }

        private ListViewItem CreateProcessNode(NtProcess entry)
        {
            try
            {
                using (NtToken token = entry.OpenToken())
                {
                    ListViewItem item = new ListViewItem(entry.ProcessId.ToString());
                    item.SubItems.Add(entry.Name);
                    item.SubItems.Add(token.User.ToString());
                    item.SubItems.Add(token.IntegrityLevel.ToString());
                    item.SubItems.Add(token.Restricted.ToString());
                    item.SubItems.Add(token.AppContainer.ToString());
                    item.Tag = entry.Duplicate();
                    return item;
                }
            }
            catch
            {
                // Do nothing
            }
            return null;
        }

        private IEnumerable<ListViewItem> CreateThreads(NtProcess entry)
        {
            List<ListViewItem> ret = new List<ListViewItem>();
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
                                ret.Add(item);
                            }
                        }
                    }
                    catch (NtException)
                    {
                    }
                }
            }
            return ret;
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
                return token.Restricted|| token.AppContainer|| token.IntegrityLevel < TokenIntegrityLevel.Medium;
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

        private void RefreshProcessList(string filter, bool hideUnrestricted)
        {
            using (var processes = new DisposableList<NtProcess>(NtProcess.GetProcesses(ProcessAccessRights.QueryLimitedInformation)))
            {
                processes.Sort((a, b) => a.ProcessId - b.ProcessId);

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

                ClearList(listViewProcesses);
                ClearList(listViewThreads);
                List<ListViewItem> procs = new List<ListViewItem>();
                List<ListViewItem> threads = new List<ListViewItem>();
                foreach (NtProcess entry in filtered)
                {
                    ListViewItem proc = CreateProcessNode(entry);
                    if (proc != null)
                    {
                        procs.Add(proc);
                    }
                    threads.AddRange(CreateThreads(entry));
                }
                listViewProcesses.Items.AddRange(procs.ToArray());
                listViewThreads.Items.AddRange(threads.ToArray());
                ResizeColumns(listViewProcesses);
                ResizeColumns(listViewThreads);
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
                ResizeColumns(listViewSessions);
            }
        }

        public MainForm()
        {
            InitializeComponent();

            listViewProcesses.ListViewItemSorter = new ListItemComparer(0);
            listViewThreads.ListViewItemSorter = new ListItemComparer(0);
            listViewSessions.ListViewItemSorter = new ListItemComparer(0);
            listViewHandles.ListViewItemSorter = new ListItemComparer(0);
            RefreshProcessList(null, false);

            using (NtToken token = NtProcess.Current.OpenToken())
            {
                if (token.SetPrivilege(TokenPrivilegeValue.SeTcbPrivilege, PrivilegeAttributes.Enabled))
                {
                    RefreshSessionList();
                }
                else
                {
                    tabControlTests.TabPages.Remove(tabPageSessions);
                }
            }
            
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
            if (listViewProcesses.SelectedItems.Count > 0)
            {
                foreach (ListViewItem item in listViewProcesses.SelectedItems)
                {
                    NtProcess process = item.Tag as NtProcess;
                    if (process != null)
                    {
                        NtToken token = GetToken(process);
                        if (token != null)
                        {
                            TokenForm.OpenForm(token, true);
                        }
                    }
                }
            }
        }

        private void btnCreateAnonymous_Click(object sender, EventArgs e)
        {
            try
            {
                TokenForm.OpenForm(TokenUtils.GetAnonymousToken(), false);
            }
            catch (NtException ex)
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
            catch (Exception ex)
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
            catch (NtException ex)
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

        private void listView_ColumnClick(object sender, ColumnClickEventArgs e)
        {
            ListItemComparer.UpdateListComparer(sender as ListView, e.Column);
        }

        private void btnRefreshSessions_Click(object sender, EventArgs e)
        {
            RefreshSessionList();
        }

        private void btnRefreshHandles_Click(object sender, EventArgs e)
        {
            ClearList(listViewHandles);
            int current_pid = Process.GetCurrentProcess().Id;
            NtToken.EnableDebugPrivilege();
            List<ListViewItem> items = new List<ListViewItem>();

            foreach (var group in NtSystemInfo.GetHandles()
                                                    .Where(h => h.ProcessId != current_pid && h.ObjectType.Equals("token", StringComparison.OrdinalIgnoreCase))
                                                    .GroupBy(h => h.ProcessId))
            {
                try
                {
                    using (NtProcess proc = NtProcess.Open(group.Key, ProcessAccessRights.DupHandle | ProcessAccessRights.QueryLimitedInformation))
                    {
                        foreach (NtHandle handle in group)
                        {
                            try
                            {
                                using (NtToken token = NtToken.DuplicateFrom(proc, new IntPtr(handle.Handle),
                                            TokenAccessRights.Query | TokenAccessRights.QuerySource))
                                {
                                    ListViewItem item = new ListViewItem(handle.ProcessId.ToString());
                                    item.SubItems.Add(proc.Name);
                                    item.SubItems.Add(String.Format("0x{0:X}", handle.Handle));
                                    item.SubItems.Add(token.User.ToString());
                                    item.SubItems.Add(token.IntegrityLevel.ToString());
                                    item.SubItems.Add(token.Restricted.ToString());
                                    item.SubItems.Add(token.AppContainer.ToString());
                                    item.SubItems.Add(token.TokenType.ToString());
                                    item.SubItems.Add(token.ImpersonationLevel.ToString());
                                    item.Tag = token.Duplicate();
                                    items.Add(item);
                                }
                            }
                            catch (NtException)
                            {
                            }
                        }
                    }
                }
                catch (NtException)
                {
                }
            }
            listViewHandles.Items.AddRange(items.ToArray());
            ResizeColumns(listViewHandles);
        }
        
        private void listViewHandles_DoubleClick(object sender, EventArgs e)
        {
            if (listViewHandles.SelectedItems.Count > 0)
            {
                NtToken token = listViewHandles.SelectedItems[0].Tag as NtToken;
                if (token != null)
                {
                    try
                    {
                        TokenForm.OpenForm(token, true);
                    }
                    catch (NtException)
                    {
                    }
                }
            }
        }

        private void toolStripMenuItemHandlesOpenToken_Click(object sender, EventArgs e)
        {
            listViewHandles_DoubleClick(sender, e);
        }
    }
}
