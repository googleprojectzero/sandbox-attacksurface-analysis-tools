//  Copyright 2017 Google Inc. All Rights Reserved.
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
using System;
using System.Collections.Generic;
using System.Linq;
using System.Management.Automation;

namespace NtObjectManager.Cmdlets.Accessible
{
    /// <summary>
    /// Common base cmdlet for commands which look at accessible resources.
    /// </summary>
    public abstract class CommonAccessBaseCmdlet : Cmdlet
    {
        /// <summary>
        /// <para type="description">Specify a list of process IDs to open for their tokens.</para>
        /// </summary>
        [Parameter]
        public int[] ProcessIds { get; set; }

        /// <summary>
        /// <para type="description">Specify a list of process names to open for their tokens.</para>
        /// </summary>
        [Parameter]
        public string[] ProcessNames { get; set; }

        /// <summary>
        /// <para type="description">Specify a list of command lines to filter on find for the process tokens.</para>
        /// </summary>
        [Parameter]
        public string[] ProcessCommandLines { get; set; }

        /// <summary>
        /// <para type="description">Specify a list token objects.</para>
        /// </summary>
        [Parameter]
        public NtToken[] Tokens { get; set; }

        /// <summary>
        /// <para type="description">Specify a list of process objects to get tokens from.</para>
        /// </summary>
        [Parameter]
        public NtProcess[] Processes { get; set; }

        private protected abstract void RunAccessCheck(IEnumerable<TokenEntry> tokens);

        private protected virtual void WriteAccessCheckResult(string name, string type_name, AccessMask granted_access,
            GenericMapping generic_mapping, SecurityDescriptor sd, Type enum_type, bool is_directory, TokenInformation token_info)
        {
            WriteObject(new CommonAccessCheckResult(name, type_name, granted_access, generic_mapping, 
                sd, enum_type, is_directory, token_info));
        }

        private static void AddTokenEntry(HashSet<TokenEntry> tokens, TokenEntry token)
        {
            if (!tokens.Add(token))
            {
                token.Dispose();
            }
        }

        private static NtToken GetTokenFromProcessDuplication(NtProcess process)
        {
            using (NtProcess dup_process = NtProcess.Open(process.ProcessId, ProcessAccessRights.QueryInformation))
            {
                using (var thread = dup_process.GetFirstThread(ThreadAccessRights.DirectImpersonation))
                {
                    if (thread == null)
                    {
                        throw new NtException(NtStatus.STATUS_ACCESS_DENIED);
                    }

                    using (NtThread.Current.ImpersonateThread(thread))
                    {
                        return NtThread.Current.OpenToken();
                    }
                }
            }
        }

        private static NtToken GetTokenFromProcessWithImpersonation(NtProcess process)
        {
            if (_system_token.Value != null)
            {
                using (_system_token.Value.Impersonate())
                {
                    using (var token = NtToken.OpenProcessToken(process,
                                            TokenAccessRights.Duplicate |
                                            TokenAccessRights.Impersonate |
                                            TokenAccessRights.Query, false))
                    {
                        if (!token.IsSuccess)
                        {
                            if (token.Status != NtStatus.STATUS_ACCESS_DENIED)
                            {
                                token.Status.ToNtException();
                            }
                        }
                        return token.Result.Duplicate();
                    }
                }
            }
            
            return GetTokenFromProcessDuplication(process);
        }

        private static void AddTokenEntryFromProcess(HashSet<TokenEntry> tokens, NtProcess process)
        {
            using (var token = NtToken.OpenProcessToken(process, false, TokenAccessRights.Query))
            {
                using (var imp_token = token.DuplicateToken(TokenType.Impersonation, SecurityImpersonationLevel.Impersonation, 
                    TokenAccessRights.Query | TokenAccessRights.Impersonate | TokenAccessRights.Duplicate, false))
                {
                    NtToken valid_imp_token = null;
                    if (!imp_token.IsSuccess)
                    {
                        if (!_has_impersonate_privilege.Value || imp_token.Status != NtStatus.STATUS_ACCESS_DENIED)
                        {
                            imp_token.Status.ToNtException();
                        }

                        valid_imp_token = GetTokenFromProcessWithImpersonation(process);
                    }
                    else
                    {
                        valid_imp_token = imp_token.Result;
                    }
                    AddTokenEntry(tokens, new TokenEntry(token, valid_imp_token, process));
                }
            }
        }

        private void GetTokensFromPids(HashSet<TokenEntry> tokens, IEnumerable<int> pids)
        {
            foreach (int pid in pids)
            {
                try
                {
                    using (NtProcess process = NtProcess.Open(pid, ProcessAccessRights.QueryLimitedInformation))
                    {
                        AddTokenEntryFromProcess(tokens, process);
                    }
                }
                catch (NtException ex)
                {
                    WriteError(new ErrorRecord(ex, "OpenTokenError", ErrorCategory.OpenError, $"pid:{pid}"));
                }
            }
        }

        private bool GetTokensFromArguments(HashSet<TokenEntry> tokens, IEnumerable<string> names, IEnumerable<string> cmdlines)
        {
            HashSet<string> names_set = new HashSet<string>(names ?? new string[0], StringComparer.OrdinalIgnoreCase);
            HashSet<string> cmdline_set = new HashSet<string>(cmdlines ?? new string[0], StringComparer.OrdinalIgnoreCase);

            if (names_set.Count > 0 || cmdline_set.Count > 0)
            {
                using (var procs = NtProcess.GetProcesses(ProcessAccessRights.QueryLimitedInformation).ToDisposableList())
                {
                    foreach (NtProcess process in procs)
                    {
                        try
                        {
                            if (names_set.Contains(process.Name))
                            {
                                AddTokenEntryFromProcess(tokens, process);
                            }
                            else
                            {
                                string curr_cmdline = process.CommandLine.ToLower();
                                foreach (string cmdline in cmdline_set)
                                {
                                    if (curr_cmdline.Contains(cmdline.ToLower()))
                                    {
                                        AddTokenEntryFromProcess(tokens, process);
                                        break;
                                    }
                                }
                            }
                        }
                        catch (NtException ex)
                        {
                            WriteError(new ErrorRecord(ex, "OpenTokenError", ErrorCategory.OpenError, process.Name));
                        }
                    }
                }
                return true;
            }
            return false;
        }

        private protected void WriteAccessWarning(string path, NtStatus status)
        {
            WriteWarning($"Couldn't access {path} - Status: {status}");
        }

        private protected void WriteAccessWarning(NtObject root, string path, NtStatus status)
        {
            WriteAccessWarning($@"{root.FullPath.TrimEnd('\\')}\{path}", status);
        }

        private class TokenEntryComparer : IEqualityComparer<TokenEntry>
        {
            public bool Equals(TokenEntry x, TokenEntry y)
            {
                return x.Information.TokenId.Equals(y.Information.TokenId);
            }

            public int GetHashCode(TokenEntry obj)
            {
                return obj.Information.TokenId.GetHashCode();
            }
        }

        /// <summary>
        /// Overridden process record method.
        /// </summary>
        protected override void ProcessRecord()
        {
            HashSet<TokenEntry> tokens = new HashSet<TokenEntry>(new TokenEntryComparer());
            try
            {
                bool explicit_tokens = false;
                NtToken.EnableDebugPrivilege();

                if (Tokens != null)
                {
                    foreach (NtToken token in Tokens)
                    {
                        AddTokenEntry(tokens, new TokenEntry(token));
                    }
                    explicit_tokens = true;
                }

                if (ProcessIds != null)
                {
                    GetTokensFromPids(tokens, ProcessIds);
                    explicit_tokens = true;
                }

                if (GetTokensFromArguments(tokens, ProcessNames, ProcessCommandLines))
                {
                    explicit_tokens = true;
                }

                if (Processes != null)
                {
                    foreach (NtProcess process in Processes)
                    {
                        AddTokenEntryFromProcess(tokens, process);
                    }
                    explicit_tokens = true;
                }

                if (tokens.Count == 0)
                {
                    if (explicit_tokens)
                    {
                        return;
                    }

                    AddTokenEntryFromProcess(tokens, NtProcess.Current);
                }

                RunAccessCheck(tokens);
            }
            finally
            {
                foreach (TokenEntry token in tokens)
                {
                    token.Dispose();
                }
            }
        }

        private static bool CheckImpersonatePrivilege()
        {
            using (var token = NtProcess.Current.OpenToken())
            {
                var priv = token.GetPrivilege(TokenPrivilegeValue.SeImpersonatePrivilege);
                return priv != null ? priv.Enabled : false;
            }
        }

        private static NtToken FindSystemToken()
        {
            using (var ps = NtProcess.GetProcesses(ProcessAccessRights.QueryLimitedInformation).ToDisposableList())
            {
                foreach (var p in ps)
                {
                    if (p.Name.Equals("services.exe", StringComparison.OrdinalIgnoreCase))
                    {
                        using (var token = NtToken.OpenProcessToken(p, TokenAccessRights.Duplicate, false))
                        {
                            if (!token.IsSuccess)
                            {
                                return null;
                            }
                            return token.Result.DuplicateToken(SecurityImpersonationLevel.Impersonation);
                        }
                    }
                }
            }
            return null;
        }

        private static Lazy<bool> _has_impersonate_privilege = new Lazy<bool>(CheckImpersonatePrivilege);
        private static Lazy<NtToken> _system_token = new Lazy<NtToken>(FindSystemToken);
    }

    /// <summary>
    /// Base class for path based accessible checks.
    /// </summary>
    public abstract class GetAccessiblePathCmdlet<A> : CommonAccessBaseWithAccessCmdlet<A>
    {
        /// <summary>
        /// <para type="description">Specify a list of native paths to check.</para>
        /// </summary>
        [Parameter(Position = 0, ParameterSetName = "path", ValueFromPipeline = true)]
        public string[] Path { get; set; }

        /// <summary>
        /// <para type="description">Specify a list of paths in a Win32 format.</para>
        /// </summary>
        [Parameter(ParameterSetName = "path")]
        public string[] Win32Path { get; set; }

        /// <summary>
        /// <para type="description">When generating the results format path in Win32 format.</para>
        /// </summary>
        [Parameter]
        public SwitchParameter FormatWin32Path { get; set; }

        /// <summary>
        /// <para type="description">Specify whether to recursively check the path for access.</para>
        /// </summary>
        [Parameter(ParameterSetName = "path")]
        public SwitchParameter Recurse { get; set; }

        /// <summary>
        /// <para type="description">When recursing specify maximum depth.</para>
        /// </summary>
        [Parameter(ParameterSetName = "path")]
        public int? MaxDepth { get; set; }

        /// <summary>
        /// Convert a Win32 path to a native path.
        /// </summary>
        /// <param name="win32_path">The Win32 path to convert.</param>
        /// <returns>The converted native path.</returns>
        protected abstract string ConvertWin32Path(string win32_path);

        /// <summary>
        /// Run an access check with a path.
        /// </summary>
        /// <param name="tokens">The list of tokens.</param>
        /// <param name="path">The path to check.</param>
        private protected abstract void RunAccessCheckPath(IEnumerable<TokenEntry> tokens, string path);

        private protected override void RunAccessCheck(IEnumerable<TokenEntry> tokens)
        {
            List<string> paths = new List<string>();
            if (Path != null)
            {
                paths.AddRange(Path);
            }

            if (Win32Path != null)
            {
                paths.AddRange(Win32Path.Select(p => ConvertWin32Path(p)));
            }

            foreach (string path in paths)
            {
                if (!path.StartsWith(@"\"))
                {
                    WriteWarning($"Path '{path}' doesn't start with \\. Perhaps you want to specify -Win32Path instead?");
                }

                try
                {
                    RunAccessCheckPath(tokens, path);
                }
                catch (NtException ex)
                {
                    WriteError(new ErrorRecord(ex, "NtException", ErrorCategory.DeviceError, this));
                }
            }
        }

        internal int GetMaxDepth()
        {
            return MaxDepth ?? int.MaxValue;
        }
    }
}