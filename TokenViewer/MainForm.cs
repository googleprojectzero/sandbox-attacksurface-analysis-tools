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

using NtApiDotNet;
using NtApiDotNet.Forms;
using NtApiDotNet.Win32;
using NtApiDotNet.Win32.Security;
using NtApiDotNet.Win32.Security.Native;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO.Pipes;
using System.Linq;
using System.Security;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace TokenViewer
{
    public partial class MainForm : Form
    {
        private class TokenGrouping
        {
            private readonly Func<ProcessTokenEntry, string> _map_to_group;

            public string Name { get; }

            public TokenGrouping(string name, Func<ProcessTokenEntry, string> map_to_group)
            {
                Name = name;
                _map_to_group = map_to_group;
            }

            public virtual Func<ProcessTokenEntry, string> CreateMapToGroup()
            {
                return _map_to_group;
            }
        }

        private class TokenGrouping<T> : TokenGrouping
        {
            private readonly Func<T> _init_func;
            private readonly Func<T, ProcessTokenEntry, string> _map_to_group;

            public TokenGrouping(string name, Func<T> init_func, Func<T, ProcessTokenEntry, string> map_to_group) 
                : base(name, null)
            {
                _init_func = init_func;
                _map_to_group = map_to_group;
            }

            public override Func<ProcessTokenEntry, string> CreateMapToGroup()
            {
                T state = _init_func();
                return p => _map_to_group(state, p);
            }
        }

        private TokenGrouping _process_grouping;

        private static void ResizeColumns(ListView view)
        {
            view.AutoResizeColumns(ColumnHeaderAutoResizeStyle.ColumnContent);
            view.AutoResizeColumns(ColumnHeaderAutoResizeStyle.HeaderSize);
        }

        private ListViewItem CreateProcessNode(NtProcess process, NtToken token)
        {
            ListViewItem item = new ListViewItem(process.ProcessId.ToString());
            item.SubItems.Add(process.Name); 
            item.SubItems.Add(token.User.ToString());
            item.SubItems.Add(token.IntegrityLevel.ToString());
            string restricted = token.Restricted.ToString();
            if (token.WriteRestricted)
            {
                restricted = "Write";
            }
            item.SubItems.Add(restricted);
            item.SubItems.Add(token.AppContainer.ToString());
            item.SubItems.Add(process.CommandLine);
            item.Tag = new ProcessTokenEntry(process, token);
            return item;
        }

        private IEnumerable<ListViewItem> CreateThreads(NtProcess process, NtToken process_token)
        {
            List<ListViewItem> ret = new List<ListViewItem>();

            using (var dup_process = process.Duplicate(ProcessAccessRights.QueryInformation, false))
            {
                if (!dup_process.IsSuccess)
                {
                    return ret;
                }

                var query_process = dup_process.Result;
                using (var threads = new DisposableList<NtThread>(query_process.GetThreads(ThreadAccessRights.MaximumAllowed)))
                {
                    foreach (NtThread thread in threads.Where(t => t.IsAccessGranted(ThreadAccessRights.QueryLimitedInformation)))
                    {
                        using (var result = NtToken.OpenThreadToken(thread, true, TokenAccessRights.MaximumAllowed, false))
                        {
                            if (!result.IsSuccess)
                                continue;
                            var token = result.Result;
                            ListViewItem item = new ListViewItem($"{query_process.ProcessId} - {query_process.Name}");
                            item.SubItems.Add(thread.ThreadId.ToString());
                            item.SubItems.Add(token.User.ToString());
                            item.SubItems.Add(token.ImpersonationLevel.ToString());
                            item.Tag = new ThreadTokenEntry(query_process, process_token,
                                thread.ThreadId, thread.Description, token,
                                thread.GetSecurityDescriptor(SecurityInformation.AllBasic, false).GetResultOrDefault());
                            ret.Add(item);
                        }
                    }
                }
            }

            return ret;
        }

        private static NtToken GetToken(NtProcess process)
        {
            var result = process.OpenToken(false);
            if (result.IsSuccess)
                return result.Result;
            return null;
        }

        private static bool IsRestrictedToken(NtToken token)
        {
            return token.IsSandbox || token.Restricted;
        }

        private void ClearList(ListView view)
        {
            foreach (ListViewItem item in view.Items)
            {
                if (item.Tag is IDisposable disp)
                {
                    disp.Dispose();
                }
            }
            view.Items.Clear();
        }

        private void RefreshProcessList(string filter, bool hideUnrestricted, bool showDeadProcesses)
        {
            listViewProcesses.BeginUpdate();
            listViewThreads.BeginUpdate();
            bool filter_name = !string.IsNullOrWhiteSpace(filter);
            ClearList(listViewProcesses);
            ClearList(listViewThreads);

            using (var list = new DisposableList<NtProcess>(NtProcess.GetProcesses(ProcessAccessRights.QueryLimitedInformation)))
            {
                List<NtProcess> processes = list.Where(p => !p.IsDeleting || showDeadProcesses).ToList();
                processes.Sort((a, b) => a.ProcessId - b.ProcessId);
                using (var tokens = new DisposableList<NtToken>(processes.Select(p => GetToken(p))))
                {
                    List<ListViewItem> threads = new List<ListViewItem>();
                    List<ListViewItem> procs = new List<ListViewItem>();

                    Debug.Assert(processes.Count == tokens.Count);
                    for (int i = 0; i < processes.Count; ++i)
                    {
                        NtProcess p = processes[i];
                        NtToken t = tokens[i];

                        if (t == null || !t.IsAccessGranted(TokenAccessRights.Query))
                        {
                            continue;
                        }

                        if (filter_name)
                        {
                            string command_line = p.CommandLine;
                            if (string.IsNullOrWhiteSpace(command_line))
                            {
                                command_line = p.Name;
                            }

                            if (!command_line.ToLower().Contains(filter.ToLower()))
                            {
                                continue;
                            }
                        }

                        if (hideUnrestricted)
                        {
                            if (!IsRestrictedToken(t))
                            {
                                continue;
                            }
                        }

                        procs.Add(CreateProcessNode(p, t));
                        threads.AddRange(CreateThreads(p, t));
                    }

                    listViewProcesses.Items.AddRange(procs.ToArray());
                    listViewThreads.Items.AddRange(threads.ToArray());
                    GroupListItems(listViewProcesses, _process_grouping);
                    ResizeColumns(listViewProcesses);
                    ResizeColumns(listViewThreads);
                }
            }
            listViewThreads.EndUpdate();
            listViewProcesses.EndUpdate();
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

        private void RefreshServiceList()
        {
            ClearList(listViewServices);
            foreach (var service in ServiceUtils.GetRunningServicesWithProcessIds())
            {
                using (var result = NtToken.OpenProcessToken(service.ProcessId, false, TokenAccessRights.MaximumAllowed | TokenAccessRights.Query, false))
                {
                    if (!result.IsSuccess)
                        continue;

                    var token = result.Result;

                    ListViewItem item = new ListViewItem(service.Name);
                    item.SubItems.Add(token.User.ToString());
                    item.SubItems.Add(service.LaunchProtected.ToString());
                    item.SubItems.Add(service.SidType.ToString());
                    item.SubItems.Add(service.DisplayName);
                    item.SubItems.Add(service.ProcessId.ToString());
                    item.Tag = new ServiceTokenEntry(service, token);
                    listViewServices.Items.Add(item);
                }
            }
            ResizeColumns(listViewServices);
        }

        private void AddGrouping(TokenGrouping grouping)
        {
            var item = groupByToolStripMenuItem.DropDownItems.Add(grouping.Name);
            item.Tag = grouping;
            item.Click += groupItemsToolStripMenuItem_Click;
        }

        private void AddGrouping<T>(string name, Func<T> init_func, Func<T, ProcessTokenEntry, string> map_to_group)
        {
            AddGrouping(new TokenGrouping<T>(name, init_func, map_to_group));
        }

        private void AddGrouping(string name, Func<ProcessTokenEntry, string> map_to_group)
        {
            AddGrouping(new TokenGrouping(name, map_to_group));
        }

        private static string GetSandboxName(NtToken token)
        {
            if (!token.IsSandbox && !token.Restricted)
            {
                return "Unsandboxed";
            }

            List<string> restrictions = new List<string>();
            if (token.AppContainer)
            {
                restrictions.Add(token.LowPrivilegeAppContainer ? "App Container (Low Privilege)" : "App Container");
            }

            if (token.Restricted)
            {
                restrictions.Add(token.WriteRestricted ? "Restricted (Write)" : "Restricted");
            }
            restrictions.Add(token.IntegrityLevel.ToString());
            return string.Join(" - ", restrictions);
        }

        private static string GetSecurityDescriptor(SecurityDescriptor sd)
        {
            return sd?.ToSddl() ?? "Unknown";
        }

        private static string GetSecurityDescriptor(NtObject obj)
        {
            return GetSecurityDescriptor(obj.GetSecurityDescriptor(SecurityInformation.AllBasic, false).GetResultOrDefault());
        }

        private static string GetElevationTypeName(NtToken token)
        {
            return string.Join(" - ", token.ElevationType, token.Elevated ? "Elevated" : "Not Elevated");
        }

        private static string GetChromeSandboxType(ProcessTokenEntry entry)
        {
            string[] args = Win32Utils.ParseCommandLine(entry.CommandLine);
            string sandbox_type = null;
            foreach (var s in args)
            {
                if (s.StartsWith("--type="))
                {
                    sandbox_type = s.Substring(7);
                    if (!sandbox_type.Equals("utility", StringComparison.OrdinalIgnoreCase))
                    {
                        break;
                    }
                }
                else if (s.StartsWith("--utility-sub-type="))
                {
                    sandbox_type = $"utility.{s.Substring(19)}";
                    break;
                }
            }
            return $"Sandbox: {sandbox_type ?? "Unknown"}";
        }

        private static string GetLogonSid(NtToken token)
        {
            return token.GetLogonSids(false).GetResultOrDefault()?.Name ?? "Unknown Logon SID";
        }

        public MainForm()
        {
            InitializeComponent();
            listViewProcesses.ListViewItemSorter = new ListItemComparer(0);
            listViewThreads.ListViewItemSorter = new ListItemComparer(0);
            listViewSessions.ListViewItemSorter = new ListItemComparer(0);
            listViewHandles.ListViewItemSorter = new ListItemComparer(0);
            listViewServices.ListViewItemSorter = new ListItemComparer(0);
            AddGrouping("Name", p => p.Name);
            AddGrouping("Session ID", p => $"Session {p.SessionId}");
            AddGrouping("Sandbox", p => GetSandboxName(p.ProcessToken));
            AddGrouping("Integrity Level", p => p.ProcessToken.IntegrityLevel.ToString());
            AddGrouping("User", p => p.ProcessToken.User.Name);
            AddGrouping("Elevation Type", p => GetElevationTypeName(p.ProcessToken));
            AddGrouping("Authentication ID", p => p.ProcessToken.AuthenticationId.ToString());
            AddGrouping("Origin ID", p => p.ProcessToken.Origin.ToString());
            AddGrouping("Flags", p => p.ProcessToken.Flags.ToString());
            AddGrouping("Package Name", p =>
            {
                if (!p.ProcessToken.AppContainer)
                    return "None";
                if (!string.IsNullOrWhiteSpace(p.ProcessToken.PackageFullName))
                    return p.ProcessToken.PackageFullName;
                return p.ProcessToken.AppContainerSid.Name;
            });
            AddGrouping("Security Descriptor", p => GetSecurityDescriptor(p.ProcessToken));
            AddGrouping("Process Security Descriptor", p => GetSecurityDescriptor(p.ProcessSecurity));
            AddGrouping("Trust Level", p => p.ProcessToken.TrustLevel?.Name ?? "Untrusted");
            AddGrouping("No Child Process", p => p.ProcessToken.NoChildProcess ? "No Child Process" : "Unrestricted");
            AddGrouping("Chrome Sandbox Type", p => GetChromeSandboxType(p));
            AddGrouping("Logon SID", p => GetLogonSid(p.ProcessToken));
            RefreshProcessList(null, false, false);

            using (NtToken token = NtProcess.Current.OpenToken())
            {
                if (token.SetPrivilege(TokenPrivilegeValue.SeTcbPrivilege, PrivilegeAttributes.Enabled))
                {
                    RefreshSessionList();
                }
                else
                {
                    tabControlTests.TabPages.Remove(tabPageSessions);
                    groupBoxServiceAccounts.Visible = false;
                }
            }

            RefreshServiceList();

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
                SecurityLogonType logon_type = (SecurityLogonType)comboBoxS4ULogonType.SelectedItem;

                if (radioLUNormal.Checked)
                {
                    SecureString str = new SecureString();
                    foreach (var ch in txtLUPassword.Text)
                    {
                        str.AppendChar(ch);
                    }

                    switch (logon_type)
                    {
                        case SecurityLogonType.Batch:
                        case SecurityLogonType.Interactive:
                        case SecurityLogonType.Network:
                        case SecurityLogonType.NetworkCleartext:
                        case SecurityLogonType.NewCredentials:
                        case SecurityLogonType.Service:
                            break;
                        default:
                            throw new ArgumentException("Invalid logon type for Logon");
                    }


                    using (NtToken token = Win32Security.LsaLogonUser(txtS4UUserName.Text, txtS4URealm.Text, str, logon_type, Logon32Provider.Default))
                    {
                        TokenForm.OpenForm(token, "LogonUser", true);
                    }
                }
                else
                {
                    using (NtToken token = TokenUtils.GetLogonS4UToken(txtS4UUserName.Text, txtS4URealm.Text, logon_type))
                    {
                        TokenForm.OpenForm(token, "S4U", true);
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
            foreach (ListViewItem item in listViewProcesses.SelectedItems)
            {
                if (item.Tag is ProcessTokenEntry entry)
                {
                    TokenForm.OpenForm(entry, $"{entry.Name}:{entry.ProcessId}", true, false);
                }
            }
        }

        private void btnCreateAnonymous_Click(object sender, EventArgs e)
        {
            try
            {
                TokenForm.OpenForm(TokenUtils.GetAnonymousToken(), "Anonymous", false);
            }
            catch (NtException ex)
            {
                MessageBox.Show(this, ex.Message, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private IEnumerable<UserGroup> GetServiceSids()
        {
            if (!checkAddServiceSid.Checked || string.IsNullOrWhiteSpace(txtServiceSid.Text))
            {
                return null;
            }

            List<Sid> groups = new List<Sid>();

            Luid logon_id = NtSystemInfo.AllocateLocallyUniqueId();
            groups.Add(new Sid(SecurityAuthority.Nt, 5, (uint)logon_id.HighPart, logon_id.LowPart));

            foreach (string sid in txtServiceSid.Text.Split(',').Select(s => s.Trim()))
            {
                groups.Add(NtSecurity.GetServiceSid(sid));
            }

            return groups.Select(s => 
                    new UserGroup(s, GroupAttributes.Enabled | GroupAttributes.EnabledByDefault | GroupAttributes.Mandatory));
        }

        private void GetServiceToken(string name)
        {
            try
            {
                IEnumerable<UserGroup> groups = GetServiceSids();
                
                TokenForm.OpenForm(Win32Security.LsaLogonUser(name, "NT AUTHORITY", null, 
                    SecurityLogonType.Service, Logon32Provider.Default, groups), "Service", false);
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
                    PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous))
                {
                    await Task.Factory.FromAsync(pipe.BeginWaitForConnection,
                        pipe.EndWaitForConnection, null);

                    NtToken token = null;
                    bool use_unc = checkBoxUseUNCPath.Checked;

                    if (pipe.IsConnected)
                    {
                        if (!use_unc)
                        {
                            byte[] buffer = new byte[1];
                            int result = await pipe.ReadAsync(buffer, 0, 1);
                        }
                        pipe.RunAsClient(() => token = NtToken.OpenThreadToken());
                        pipe.Disconnect();
                    }

                    if (token != null)
                    {
                        TokenForm.OpenForm(token, "NamedPipe", false);
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

        private async void btnPipeConnect_Click(object sender, EventArgs e)
        {
            try
            {
                bool use_unc = checkBoxUseUNCPath.Checked;
                using (NamedPipeClientStream pipe = new NamedPipeClientStream(use_unc ? "localhost" : ".", 
                    txtPipeName.Text, PipeDirection.Out))
                {
                    await pipe.ConnectAsync(1000);
                    if (!use_unc)
                    {
                        byte[] buffer = new byte[1];
                        await pipe.WriteAsync(buffer, 0, 1);
                    }
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
                TokenForm.OpenForm(new ProcessTokenEntry(NtProcess.Current), "Current", false, false);
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
                TokenForm.OpenForm(TokenUtils.GetTokenFromClipboard(), "Clipboard", false);
            }
            catch (NtException ex)
            {
                MessageBox.Show(this, ex.Message, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void refreshToolStripMenuItem_Click(object sender, EventArgs e)
        {
            RefreshProcessList(txtFilter.Text, checkBoxUnrestricted.Checked, showDeadProcessesToolStripMenuItem.Checked);
        }

        private void btnFilter_Click(object sender, EventArgs e)
        {
            RefreshProcessList(txtFilter.Text, checkBoxUnrestricted.Checked, showDeadProcessesToolStripMenuItem.Checked);
        }
        
        private void toolStripMenuItemOpenThreadToken_Click(object sender, EventArgs e)
        {
            if (listViewThreads.SelectedItems.Count > 0)
            {
                if (listViewThreads.SelectedItems[0].Tag is ThreadTokenEntry thread)
                {
                    if (thread.ThreadToken != null)
                    {
                        TokenForm.OpenForm(thread, $"{thread.Name}:{thread.ProcessId}.{thread.ThreadId}", true, true);
                    }
                }
            }
        }

        private void openProcessTokenToolStripMenuItem_Click(object sender, EventArgs e)
        {
            if (listViewThreads.SelectedItems.Count > 0)
            {
                if (listViewThreads.SelectedItems[0].Tag is ThreadTokenEntry thread)
                {
                    if (thread.ProcessToken != null)
                    {
                        TokenForm.OpenForm(thread, $"{thread.Name}:{thread.ProcessId}", true, false);
                    }
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
                if (listViewSessions.SelectedItems[0].Tag is NtToken token)
                {
                    TokenForm.OpenForm(token, "Session", true);
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
                using (var proc = NtProcess.Open(group.Key, ProcessAccessRights.DupHandle | ProcessAccessRights.QueryLimitedInformation, false))
                {
                    if (!proc.IsSuccess)
                    {
                        continue;
                    }

                    foreach (NtHandle handle in group)
                    {
                        using (var token_result = NtToken.DuplicateFrom(proc.Result, new IntPtr(handle.Handle), 
                            TokenAccessRights.Query | TokenAccessRights.QuerySource, DuplicateObjectOptions.None, false))
                        {
                            if (!token_result.IsSuccess)
                            {
                                continue;
                            }
                            NtToken token = token_result.Result;
                            ListViewItem item = new ListViewItem(handle.ProcessId.ToString());
                            item.SubItems.Add(proc.Result.Name);
                            item.SubItems.Add($"0x{handle.Handle:X}");
                            item.SubItems.Add(token.User.ToString());
                            item.SubItems.Add(token.IntegrityLevel.ToString());
                            string restricted = token.Restricted.ToString();
                            if (token.WriteRestricted)
                            {
                                restricted = "Write";
                            }
                            item.SubItems.Add(restricted);
                            item.SubItems.Add(token.AppContainer.ToString());
                            item.SubItems.Add(token.TokenType.ToString());
                            item.SubItems.Add(token.ImpersonationLevel.ToString());
                            item.Tag = token.Duplicate();
                            items.Add(item);
                        }
                    }
                }
            }
            listViewHandles.Items.AddRange(items.ToArray());
            ResizeColumns(listViewHandles);
        }
        
        private void listViewHandles_DoubleClick(object sender, EventArgs e)
        {
            if (listViewHandles.SelectedItems.Count > 0)
            {
                if (listViewHandles.SelectedItems[0].Tag is NtToken token)
                {
                    try
                    {
                        TokenForm.OpenForm(token, "Handle", true);
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

        private void checkAddServiceSid_CheckedChanged(object sender, EventArgs e)
        {
            txtServiceSid.Enabled = checkAddServiceSid.Checked;
        }

        private void showDeadProcessesToolStripMenuItem_Click(object sender, EventArgs e)
        {
            showDeadProcessesToolStripMenuItem.Checked = !showDeadProcessesToolStripMenuItem.Checked;
            RefreshProcessList(txtFilter.Text, checkBoxUnrestricted.Checked, showDeadProcessesToolStripMenuItem.Checked);
        }

        private void ShowProcessSecurity(ProcessTokenEntry process)
        {
            if (process.ProcessSecurity != null)
            {
                var viewer = new SecurityDescriptorViewerForm($"{process.Name}:{process.ProcessId}",
                    process.ProcessSecurity, NtType.GetTypeByType<NtProcess>(), false);
                viewer.ShowDialog(this);
            }
        }

        private void showProcessSecurityToolStripMenuItem_Click(object sender, EventArgs e)
        {
            if (listViewProcesses.SelectedItems.Count > 0)
            {
                if (listViewProcesses.SelectedItems[0].Tag is ProcessTokenEntry entry)
                {
                    ShowProcessSecurity(entry);
                }
            }
        }

        private void showThreadSecurityToolStripMenuItem_Click(object sender, EventArgs e)
        {
            if (listViewThreads.SelectedItems.Count > 0)
            {
                if (listViewThreads.SelectedItems[0].Tag is ThreadTokenEntry thread)
                {
                    if (thread.ThreadSecurity != null)
                    {
                        var viewer = new SecurityDescriptorViewerForm($"{thread.Name}:{thread.ProcessId}.{thread.ThreadId}",
                            thread.ThreadSecurity, NtType.GetTypeByType<NtThread>(), false);
                        viewer.ShowDialog(this);
                    }
                }
            }
        }

        private void showProcessSecurityToolStripMenuItem1_Click(object sender, EventArgs e)
        {
            if (listViewThreads.SelectedItems.Count > 0)
            {
                if (listViewThreads.SelectedItems[0].Tag is ThreadTokenEntry thread)
                {
                    if (thread.ProcessSecurity != null)
                    {
                        ShowProcessSecurity(thread);
                    }
                }
            }
        }

        private void txtFilter_KeyPress(object sender, KeyPressEventArgs e)
        {
            if (e.KeyChar == '\r')
            {
                btnFilter_Click(sender, e);
            }
        }

        private void checkBoxUnrestricted_CheckedChanged(object sender, EventArgs e)
        {
            RefreshProcessList(txtFilter.Text, checkBoxUnrestricted.Checked, showDeadProcessesToolStripMenuItem.Checked);
        }

        private static void GroupListItems(ListView listView, TokenGrouping grouping)
        {
            listView.BeginUpdate();
            Dictionary<string, List<ListViewItem>> groups = new Dictionary<string, List<ListViewItem>>();
            listView.Groups.Clear();

            var map_to_group = grouping?.CreateMapToGroup();

            foreach (ListViewItem item in listView.Items)
            {
                if (map_to_group == null)
                {
                    item.Group = null;
                    continue;
                }
                if (item.Tag is ProcessTokenEntry entry)
                {
                    string group_name = map_to_group(entry);
                    if (!groups.ContainsKey(group_name))
                    {
                        groups.Add(group_name, new List<ListViewItem>());
                    }
                    groups[group_name].Add(item);
                }
            }

            foreach (var pair in groups.OrderBy(p => p.Key))
            {
                var group = new ListViewGroup(pair.Key, HorizontalAlignment.Left);
                listView.Groups.Add(group);
                group.Items.AddRange(pair.Value.ToArray());
            }
            listView.EndUpdate();
        }

        private void groupItemsToolStripMenuItem_Click(object sender, EventArgs e)
        {
            if (sender is ToolStripMenuItem tool_strip)
            {
                foreach (var item in tool_strip.GetCurrentParent().Items.OfType<ToolStripMenuItem>())
                {
                    item.Checked = false;
                }
                tool_strip.Checked = true;
                _process_grouping = tool_strip.Tag as TokenGrouping;
                GroupListItems(listViewProcesses, _process_grouping);
            }
            else
            {
                GroupListItems(listViewProcesses, _process_grouping);
            }
        }

        private void contextMenuStripProcesses_Opening(object sender, System.ComponentModel.CancelEventArgs e)
        {
            if (listViewProcesses.SelectedItems.Count > 0)
            {
                if (listViewProcesses.SelectedItems[0].Tag is ProcessTokenEntry process)
                {
                    showProcessSecurityToolStripMenuItem.Enabled = process.ProcessSecurity != null;
                }
            }
        }

        private void contextMenuStripThreads_Opening(object sender, System.ComponentModel.CancelEventArgs e)
        {
            if (listViewThreads.SelectedItems.Count > 0)
            {
                if (listViewThreads.SelectedItems[0].Tag is ThreadTokenEntry thread)
                {
                    showProcessSecurityToolStripMenuItem1.Enabled = thread.ProcessSecurity != null;
                    showThreadSecurityToolStripMenuItem.Enabled = thread.ThreadSecurity != null;
                }
            }
        }

        private void openServiceTokenToolStripMenuItem_Click(object sender, EventArgs e)
        {
            foreach (ListViewItem item in listViewServices.SelectedItems)
            {
                if (item.Tag is ServiceTokenEntry entry)
                {
                    TokenForm.OpenForm(entry.ProcessToken, entry.Service.Name, true);
                }
            }
        }

        private void showServiceSecurityToolStripMenuItem_Click(object sender, EventArgs e)
        {
            if (listViewServices.SelectedItems.Count > 0)
            {
                if (listViewServices.SelectedItems[0].Tag is ServiceTokenEntry service)
                {
                    if (service.Service.SecurityDescriptor != null)
                    {
                        var viewer = new SecurityDescriptorViewerForm(service.Service.Name,
                            service.Service.SecurityDescriptor, NtType.GetTypeByName(ServiceUtils.SERVICE_NT_TYPE_NAME, false), false);
                        viewer.ShowDialog(this);
                    }
                }
            }
        }

        private void refreshServicesToolStripMenuItem_Click(object sender, EventArgs e)
        {
            RefreshServiceList();
        }
    }
}
