//  Copyright 2016 Google Inc. All Rights Reserved.
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
using System.Management.Automation;

namespace NtObjectManager
{
    /// <summary>
    /// Get token base cmdlet.
    /// </summary>
    public abstract class GetNtTokenCmdlet : Cmdlet
    {
        /// <summary>
        /// <para type="description">Specify access rights for the token.</para>
        /// </summary>
        [Parameter]
        public TokenAccessRights Access { get; set; }

        /// <summary>
        /// <para type="description">Return a duplicated version of the time. The type of token is specified using -TokenType and -ImpersonationLevel</para>
        /// </summary>
        [Parameter]
        public SwitchParameter Duplicate { get; set; }

        /// <summary>
        /// <para type="description">Specify the type of token to create if -Duplicate is specified.</para>
        /// </summary>
        [Parameter]
        public TokenType TokenType { get; set; }

        /// <summary>
        /// <para type="description">Specify the impersonation level of the token to create if -Duplicate is specified and TokenType is Impersonation.</para>
        /// </summary>
        [Parameter]
        public SecurityImpersonationLevel ImpersonationLevel { get; set; }

        /// <summary>
        /// Constructor.
        /// </summary>
        public GetNtTokenCmdlet()
        {
            Access = TokenAccessRights.MaximumAllowed;
            TokenType = TokenType.Impersonation;
            ImpersonationLevel = SecurityImpersonationLevel.Impersonation;
        }

        /// <summary>
        /// Get token for this cmdlet.
        /// </summary>
        /// <param name="desired_access">The token access required.</param>
        /// <returns>The token object.</returns>
        protected abstract NtToken GetToken(TokenAccessRights desired_access);

        /// <summary>
        /// Overridden ProcessRecord method.
        /// </summary>
        protected override void ProcessRecord()
        {
            NtToken token = null;
            if (Duplicate)
            {
                using (NtToken base_token = GetToken(TokenAccessRights.Duplicate))
                {
                    token = base_token.DuplicateToken(TokenType, ImpersonationLevel, Access);
                }
            }
            else
            {
                token = GetToken(Access);
            }
            WriteObject(token);
        }
    }

    /// <summary>
    /// <para type="synopsis">Open primary NT token from a process.</para>
    /// <para type="description">This cmdlet gets a primary token from a process. You can specify a specific process -Process parameter otherwise the current process is used.</para>
    /// <para>Note that tokens objects need to be disposed of after use, therefore capture them in a Dispose List or manually Close them once used.</para>
    /// </summary>
    /// <example>
    ///   <code>$obj = Get-NtTokenPrimary</code>
    ///   <para>Get current process' primary token.</para>
    /// </example>
    /// <example>
    ///   <code>$obj = Get-NtTokenPrimary -Access Duplicate</code>
    ///   <para>Get current process' primary token for Duplicate access.</para>
    /// </example>
    /// <example>
    ///   <code>$obj = Get-NtTokenPrimary -Duplicate -TokenType Impersonation -ImpersonationLevel Impersonation</code>
    ///   <para>Get current process' primary token and convert to an impersonation token.</para>
    /// </example>
    /// <example>
    ///   <code>$obj = Get-NtTokenPrimary -Access AdjustPrivileges&#x0A;$obj.SetPrivilege("SeDebugPrivilege", $true)</code>
    ///   <para>Enable debug privilege on current token.</para>
    /// </example>
    /// <example>
    ///   <code>$obj = Get-NtTokenPrimary&#x0A;$obj.GetPrivileges()</code>
    ///   <para>Query the privileges of a token.</para>
    /// </example>
    /// <example>
    ///   <code>$obj = Get-NtTokenPrimary&#x0A;$obj.GetGroups()</code>
    ///   <para>Query the groups of a token.</para>
    /// </example>
    /// <para type="link">about_ManagingNtObjectLifetime</para>
    [Cmdlet(VerbsCommon.Get, "NtTokenPrimary")]
    public sealed class GetNtTokenPrimaryCmdlet : GetNtTokenCmdlet
    {
        /// <summary>
        /// <para type="description">Specify the process to open the token from. If not set will use the current process.</para>
        /// </summary>
        [Parameter]
        public NtProcess Process { get; set; }

        /// <summary>
        /// Get token for this cmdlet.
        /// </summary>
        /// <param name="desired_access">The token access required.</param>
        /// <returns>The token object.</returns>
        protected override NtToken GetToken(TokenAccessRights desired_access)
        {
            return NtToken.OpenProcessToken(Process ?? NtProcess.Current, Duplicate, desired_access);
        }
    }

    /// <summary>
    /// <para type="synopsis">Open impersonation NT token from a thread.</para>
    /// <para type="description">This cmdlet gets an impersonation token from a thread. You can specify a specific thread -Thread parameter otherwise the current thread is used.</para>
    /// <para>Note that tokens objects need to be disposed of after use, therefore capture them in a Dispose List or manually Close them once used.</para>
    /// </summary>
    /// <example>
    ///   <code>$obj = Get-NtTokenThread</code>
    ///   <para>Get current threads primary token.</para>
    /// </example>
    /// <example>
    ///   <code>$obj = Get-NtTokenThread -Access Duplicate</code>
    ///   <para>Get current threads primary token for Duplicate access.</para>
    /// </example>
    /// <example>
    ///   <code>$obj = Get-NtTokenThread -Duplicate -TokenType Primary</code>
    ///   <para>Get current threads primary token and convert to an primary token.</para>
    /// </example>
    /// <example>
    ///   <code>$obj = Get-NtTokenThread -Access AdjustPrivileges&#x0A;$obj.SetPrivilege("SeDebugPrivilege", $true)</code>
    ///   <para>Enable debug privilege on current token.</para>
    /// </example>
    /// <example>
    ///   <code>$obj = Get-NtTokenThread&#x0A;$obj.GetPrivileges()</code>
    ///   <para>Query the privileges of a token.</para>
    /// </example>
    /// <example>
    ///   <code>$obj = Get-NtTokenThread&#x0A;$obj.GetGroups()</code>
    ///   <para>Query the groups of a token.</para>
    /// </example>
    /// <para type="link">about_ManagingNtObjectLifetime</para>
    [Cmdlet(VerbsCommon.Get, "NtTokenThread")]
    public class GetNtTokenThreadCmdlet : GetNtTokenCmdlet
    {
        /// <summary>
        /// <para type="description">Specify the thread to open the token from. If not set will use the current thread.</para>
        /// </summary>
        [Parameter]
        public NtThread Thread { get; set; }

        /// <summary>
        /// <para type="description">Specify the token should be open with the process identity rather than the impersonated identity.</para>
        /// </summary>
        [Parameter]
        public bool OpenAsSelf { get; set; }

        /// <summary>
        /// Get token for this cmdlet.
        /// </summary>
        /// <param name="desired_access">The token access required.</param>
        /// <returns>The token object.</returns>
        protected override NtToken GetToken(TokenAccessRights desired_access)
        {
            return NtToken.OpenThreadToken(Thread ?? NtThread.Current, OpenAsSelf, false, desired_access);
        }
    }

    /// <summary>
    /// <para type="synopsis">Open the effective NT token from a thread.</para>
    /// <para type="description">This cmdlet gets a the effective token from a thread. If the thread is not currently impersonating the associated process primary token will be opened instead.
    /// You can specify a specific thread -Thread parameter otherwise the current thread is used.</para>
    /// <para>Note that tokens objects need to be disposed of after use, therefore capture them in a Dispose List or manually Close them once used.</para>
    /// </summary>
    /// <example>
    ///   <code>$obj = Get-NtTokenEffective</code>
    ///   <para>Get current threads primary token.</para>
    /// </example>
    /// <example>
    ///   <code>$obj = Get-NtTokenEffective -Access Duplicate</code>
    ///   <para>Get current threads primary token for Duplicate access.</para>
    /// </example>
    /// <example>
    ///   <code>$obj = Get-NtTokenEffective -Duplicate -TokenType Primary</code>
    ///   <para>Get current threads primary token and convert to an primary token.</para>
    /// </example>
    /// <example>
    ///   <code>$obj = Get-NtTokenEffective -Access AdjustPrivileges&#x0A;$obj.SetPrivilege("SeDebugPrivilege", $true)</code>
    ///   <para>Enable debug privilege on current token.</para>
    /// </example>
    /// <example>
    ///   <code>$obj = Get-NtTokenEffective&#x0A;$obj.GetPrivileges()</code>
    ///   <para>Query the privileges of a token.</para>
    /// </example>
    /// <example>
    ///   <code>$obj = Get-NtTokenEffective&#x0A;$obj.GetGroups()</code>
    ///   <para>Query the groups of a token.</para>
    /// </example>
    /// <para type="link">about_ManagingNtObjectLifetime</para>
    [Cmdlet(VerbsCommon.Get, "NtTokenEffective")]
    public sealed class GetNtTokenEffectiveCmdlet : GetNtTokenThreadCmdlet
    {
        /// <summary>
        /// Get token for this cmdlet.
        /// </summary>
        /// <param name="desired_access">The token access required.</param>
        /// <returns>The token object.</returns>
        protected override NtToken GetToken(TokenAccessRights desired_access)
        {
            NtToken token = base.GetToken(desired_access);
            if (token == null)
            {
                if (Thread == null)
                {
                    token = NtToken.OpenProcessToken(NtProcess.Current, false, desired_access);
                }
                else
                {
                    token = NtToken.OpenProcessToken(Thread.ProcessId, false, desired_access);
                }
            }
            return token;
        }
    }
}
