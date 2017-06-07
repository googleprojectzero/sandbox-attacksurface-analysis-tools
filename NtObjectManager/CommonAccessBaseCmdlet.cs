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
using System.Management.Automation;

namespace NtObjectManager
{
    /// <summary>
    /// Class to represent an access check result.
    /// </summary>
    public class AccessCheckResult
    {
        /// <summary>
        /// The name of the object which was accessed (depends on the type).
        /// </summary>
        public string Name { get; private set; }

        /// <summary>
        /// Name of the type accessed.
        /// </summary>
        public string TypeName { get; private set; }
        
        /// <summary>
        /// Granted access.
        /// </summary>
        public AccessMask GrantedAccess { get; private set; }

        /// <summary>
        /// Get granted access as a type specific string
        /// </summary>
        public string GrantedAccessString { get; private set; }

        /// <summary>
        /// Get granted access as generic access string.
        /// </summary>
        public string GrantedGenericAccessString { get; private set; }

        /// <summary>
        /// The generic mapping associated with this type.
        /// </summary>
        public GenericMapping GenericMapping { get; private set; }

        /// <summary>
        /// The security descriptor associated with this access check.
        /// </summary>
        public string SecurityDescriptor { get; private set; }

        /// <summary>
        /// Information the token used in the access check.
        /// </summary>
        public TokenInformation TokenInfo { get; private set; }

        /// <summary>
        /// Was read access granted?
        /// </summary>
        public bool IsRead { get; private set; }

        /// <summary>
        /// Was write access granted?
        /// </summary>
        public bool IsWrite { get; private set; }

        /// <summary>
        /// Was execute access granted?
        /// </summary>
        public bool IsExecute { get; private set; }

        /// <summary>
        /// Was all access granted?
        /// </summary>
        public bool IsAll { get; private set; }

        /// <summary>
        /// Unique key for access check result (based on TokenId)
        /// </summary>
        public long TokenId { get; private set; }

        internal AccessCheckResult(string name, string type_name, AccessMask granted_access, 
            GenericMapping generic_mapping, string sddl, Type enum_type, TokenInformation token_info)
        {
            Name = name;
            TypeName = type_name;
            GrantedAccess = granted_access;
            GenericMapping = generic_mapping;
            TokenInfo = token_info;
            SecurityDescriptor = sddl;
            IsRead = generic_mapping.HasRead(granted_access);
            IsWrite = generic_mapping.HasWrite(granted_access);
            IsExecute = generic_mapping.HasExecute(granted_access);
            IsAll = generic_mapping.HasAll(granted_access);
            GrantedAccessString = NtObjectUtils.GrantedAccessAsString(granted_access, generic_mapping, enum_type, false);
            GrantedGenericAccessString = NtObjectUtils.GrantedAccessAsString(granted_access, generic_mapping, enum_type, true);
            TokenId = token_info.TokenId.ToInt64();
        }
    }    

    /// <summary>
    /// Information about a token.
    /// </summary>
    public sealed class TokenInformation
    {
        /// <summary>
        /// Token username
        /// </summary>
        public Sid UserName { get; private set; }
        /// <summary>
        /// Token integrity level
        /// </summary>
        public TokenIntegrityLevel IntegrityLevel { get; private set; }
        /// <summary>
        /// Token type
        /// </summary>
        public TokenType TokenType { get; private set; }
        /// <summary>
        /// Token impersonation level
        /// </summary>
        public SecurityImpersonationLevel ImpersonationLevel { get; private set; }
        /// <summary>
        /// Token ID
        /// </summary>
        public Luid TokenId { get; private set; }
        /// <summary>
        /// Elevated token
        /// </summary>
        public bool Elevated { get; private set; }
        /// <summary>
        /// Restricted token
        /// </summary>
        public bool Restricted { get; private set; }
        /// <summary>
        /// App container token
        /// </summary>
        public bool AppContainer { get; private set; }
        /// <summary>
        /// App container SID (if an AppContainer)
        /// </summary>
        public Sid AppContainerSid { get; private set; }
        /// <summary>
        /// Low privilege AC
        /// </summary>
        public bool LowPrivilegeAppContainer { get; private set; }
        /// <summary>
        /// Additonal information of where the token was sourced from
        /// </summary>
        public Dictionary<string, object> SourceData { get; private set; }

        internal TokenInformation(NtToken token)
        {
            SourceData = new Dictionary<string, object>();
            TokenId = token.Id;
            UserName = token.User.Sid;
            IntegrityLevel = token.IntegrityLevel;
            TokenType = token.TokenType;
            ImpersonationLevel = token.ImpersonationLevel;
            AppContainer = token.AppContainer;
            AppContainerSid = token.AppContainerSid;
            Elevated = token.Elevated;
            Restricted = token.Restricted;
            LowPrivilegeAppContainer = token.LowPrivilegeAppContainer;
        }

        internal TokenInformation(NtToken token, NtProcess process) 
            : this(token)
        {
            SourceData["ProcessId"] = process.ProcessId;
            SourceData["Name"] = process.Name;
            SourceData["ImagePath"] = process.GetImageFilePath(false);
            SourceData["CommandLine"] = process.CommandLine;
        }
    }

    internal struct TokenEntry : IDisposable
    {
        public readonly NtToken Token;
        public readonly TokenInformation Information;

        private static NtToken DuplicateToken(NtToken token)
        {
            if (token.TokenType == TokenType.Primary)
            {
                return token.DuplicateToken(TokenType.Impersonation, SecurityImpersonationLevel.Impersonation,
                    TokenAccessRights.Query | TokenAccessRights.Impersonate | TokenAccessRights.Duplicate);
            }
            else
            {
                return token.Duplicate(TokenAccessRights.Query | TokenAccessRights.Impersonate | TokenAccessRights.Duplicate);
            }
        }

        public TokenEntry(NtToken token)
        {
            Information = new TokenInformation(token);
            Token = DuplicateToken(token);
        }

        public TokenEntry(NtToken token, NtProcess process)
        {
            Information = new TokenInformation(token, process);
            Token = DuplicateToken(token);
        }

        public void Dispose()
        {
            Token?.Dispose();
        }
    }

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

        internal abstract void RunAccessCheck(IEnumerable<TokenEntry> tokens);

        internal void WriteAccessCheckResult(string name, string type_name, AccessMask granted_access,
            GenericMapping generic_mapping, string sddl, Type enum_type, TokenInformation proc_info)
        {
            WriteObject(new AccessCheckResult(name, type_name, granted_access, generic_mapping, sddl, enum_type, proc_info));
        }

        private static void AddTokenEntry(HashSet<TokenEntry> tokens, TokenEntry token)
        {
            if (!tokens.Add(token))
            {
                token.Dispose();
            }
        }

        private static void AddTokenEntryFromProcess(HashSet<TokenEntry> tokens, NtProcess process)
        {
            using (NtToken token = NtToken.OpenProcessToken(process, false,
                                            TokenAccessRights.Duplicate |
                                            TokenAccessRights.Impersonate |
                                            TokenAccessRights.Query))
            {
                AddTokenEntry(tokens, new TokenEntry(token, process));
            }
        }

        private void GetTokensFromPids(HashSet<TokenEntry> tokens, IEnumerable<int> pids)
        {
            foreach (int pid in pids)
            {
                using (NtProcess process = NtProcess.Open(pid, ProcessAccessRights.QueryLimitedInformation))
                {
                    AddTokenEntryFromProcess(tokens, process);
                }
            }
        }

        private void GetTokensFromArguments(HashSet<TokenEntry> tokens, IEnumerable<string> names, IEnumerable<string> cmdlines)
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
                                foreach (string cmdline in cmdlines)
                                {
                                    if (curr_cmdline.Contains(cmdline.ToLower()))
                                    {
                                        AddTokenEntryFromProcess(tokens, process);
                                        break;
                                    }
                                }
                            }
                        }
                        catch (NtException)
                        {
                        }
                    }
                }
            }
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
                NtToken.EnableDebugPrivilege();

                if (Tokens != null)
                {
                    foreach (NtToken token in Tokens)
                    {
                        AddTokenEntry(tokens, new TokenEntry(token));
                    }
                }
                if (ProcessIds != null)
                {
                    GetTokensFromPids(tokens, ProcessIds);
                }
                GetTokensFromArguments(tokens, ProcessNames, ProcessCommandLines);
                if (tokens.Count == 0)
                {
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
    }
}
