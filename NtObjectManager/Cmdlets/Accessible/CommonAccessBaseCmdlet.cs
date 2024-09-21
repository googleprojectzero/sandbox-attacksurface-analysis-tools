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

using NtCoreLib;
using NtCoreLib.Security.Authorization;
using NtCoreLib.Security.Token;
using System;
using System.Collections.Generic;
using System.Management.Automation;

namespace NtObjectManager.Cmdlets.Accessible;

/// <summary>
/// Common base cmdlet for commands which look at accessible resources.
/// </summary>
public abstract class CommonAccessBaseCmdlet : PSCmdlet
{
    /// <summary>
    /// <para type="description">Specify a list of process IDs to open for their tokens.</para>
    /// </summary>
    [Parameter]
    [Alias("ProcessIds")]
    public int[] ProcessId { get; set; }

    /// <summary>
    /// <para type="description">Specify a list of process names to open for their tokens.</para>
    /// </summary>
    [Parameter]
    [Alias("ProcessNames")]
    public string[] ProcessName { get; set; }

    /// <summary>
    /// <para type="description">Specify a list of command lines to filter on find for the process tokens.</para>
    /// </summary>
    [Parameter]
    [Alias("ProcessCommandLines")]
    public string[] ProcessCommandLine { get; set; }

    /// <summary>
    /// <para type="description">Specify a list token objects.</para>
    /// </summary>
    [Parameter]
    [Alias("Tokens")]
    public NtToken[] Token { get; set; }

    /// <summary>
    /// <para type="description">Specify a list of process objects to get tokens from.</para>
    /// </summary>
    [Parameter]
    [Alias("Processes")]
    public NtProcess[] Process { get; set; }

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
        using NtProcess dup_process = NtProcess.Open(process.ProcessId, ProcessAccessRights.QueryInformation);
        using var thread = dup_process.GetFirstThread(ThreadAccessRights.DirectImpersonation);
        if (thread == null)
        {
            throw new NtException(NtStatus.STATUS_ACCESS_DENIED);
        }

        using (NtThread.Current.ImpersonateThread(thread))
        {
            return NtThread.Current.OpenToken();
        }
    }

    private static NtToken GetTokenFromProcessWithImpersonation(NtProcess process)
    {
        if (_system_token.Value != null)
        {
            using (_system_token.Value.Impersonate())
            {
                using var token = NtToken.OpenProcessToken(process,
                                        TokenAccessRights.Duplicate |
                                        TokenAccessRights.Impersonate |
                                        TokenAccessRights.Query, false);
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
        
        return GetTokenFromProcessDuplication(process);
    }

    private static void AddTokenEntryFromProcess(HashSet<TokenEntry> tokens, NtProcess process)
    {
        using var token = NtToken.OpenProcessToken(process, false, TokenAccessRights.Query);
        using var imp_token = token.DuplicateToken(TokenType.Impersonation, SecurityImpersonationLevel.Impersonation,
            TokenAccessRights.Query | TokenAccessRights.Impersonate | TokenAccessRights.Duplicate, false);
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

    private void GetTokensFromPids(HashSet<TokenEntry> tokens, IEnumerable<int> pids)
    {
        foreach (int pid in pids)
        {
            try
            {
                using NtProcess process = NtProcess.Open(pid, ProcessAccessRights.QueryLimitedInformation);
                AddTokenEntryFromProcess(tokens, process);
            }
            catch (NtException ex)
            {
                WriteError(new ErrorRecord(ex, "OpenTokenError", ErrorCategory.OpenError, $"pid:{pid}"));
            }
        }
    }

    private bool GetTokensFromArguments(HashSet<TokenEntry> tokens, IEnumerable<string> names, IEnumerable<string> cmdlines)
    {
        HashSet<string> names_set = new(names ?? new string[0], StringComparer.OrdinalIgnoreCase);
        HashSet<string> cmdline_set = new(cmdlines ?? new string[0], StringComparer.OrdinalIgnoreCase);

        if (names_set.Count > 0 || cmdline_set.Count > 0)
        {
            using var procs = NtProcess.GetProcesses(ProcessAccessRights.QueryLimitedInformation).ToDisposableList();
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
        HashSet<TokenEntry> tokens = new(new TokenEntryComparer());
        try
        {
            bool explicit_tokens = false;
            NtToken.EnableDebugPrivilege();

            if (Token != null)
            {
                foreach (NtToken token in Token)
                {
                    AddTokenEntry(tokens, new TokenEntry(token));
                }
                explicit_tokens = true;
            }

            if (ProcessId != null)
            {
                GetTokensFromPids(tokens, ProcessId);
                explicit_tokens = true;
            }

            if (GetTokensFromArguments(tokens, ProcessName, ProcessCommandLine))
            {
                explicit_tokens = true;
            }

            if (Process != null)
            {
                foreach (NtProcess process in Process)
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
        using var token = NtProcess.Current.OpenToken();
        var priv = token.GetPrivilege(TokenPrivilegeValue.SeImpersonatePrivilege);
        return priv != null ? priv.Enabled : false;
    }

    private static NtToken FindSystemToken()
    {
        using var ps = NtProcess.GetProcesses(ProcessAccessRights.QueryLimitedInformation).ToDisposableList();
        foreach (var p in ps)
        {
            if (p.Name.Equals("services.exe", StringComparison.OrdinalIgnoreCase))
            {
                using var token = NtToken.OpenProcessToken(p, TokenAccessRights.Duplicate, false);
                if (!token.IsSuccess)
                {
                    return null;
                }
                return token.Result.DuplicateToken(SecurityImpersonationLevel.Impersonation);
            }
        }
        return null;
    }

    private protected bool HasSecurityPrivilege()
    {
        if (!_has_security_privilege.HasValue)
        {
            using var token = NtToken.OpenProcessToken();
            _has_security_privilege = token.GetPrivilege(TokenPrivilegeValue.SeSecurityPrivilege)?.Enabled ?? false;
        }
        return _has_security_privilege.Value;
    }

    private bool? _has_security_privilege;
    private static readonly Lazy<bool> _has_impersonate_privilege = new(CheckImpersonatePrivilege);
    private static readonly Lazy<NtToken> _system_token = new(FindSystemToken);
}