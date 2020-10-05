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
using System;
using System.Management.Automation;
using NtObjectManager.Utils;

namespace NtObjectManager.Cmdlets.Object
{
    /// <summary>
    /// <para type="synopsis">Invokes a script block while impersonating a token.</para>
    /// <para type="description">This cmdlet invokes a script block while impersonating a token. Optionally can impersonate the anonymous token directly.</para>
    /// </summary>
    /// <example>
    ///   <code>Invoke-NtToken -Token $token -Script { Get-NtFile \Path\To\File }</code>
    ///   <para>Open a file under impersonation.</para>
    /// </example>
    /// <example>
    ///   <code>Invoke-NtToken -Token $token -ImpersonationLevel Identification -Script { Get-NtToken -Impersonation -OpenAsSelf }</code>
    ///   <para>Open the impersontation token under identification level impersonation.</para>
    /// </example>
    /// <example>
    ///   <code>Invoke-NtToken -Script { Get-NtProcess -ProcessId 1234 } -Anonymous</code>
    ///   <para>Open a process while impersonating the anonymous token.</para>
    /// </example>
    /// <example>
    ///   <code>Invoke-NtToken -Script { Get-NtProcess -ProcessId 1234 } -System</code>
    ///   <para>Open a process while impersonating a system token. Needs administrator privileges.</para>
    /// </example>
    /// <example>
    ///   <code>Invoke-NtToken -Script { Get-NtProcess -ProcessId 1234 } -Current -ImpersonationLevel Identification </code>
    ///   <para>Open a process while impersonating a current token at identitification level.</para>
    /// </example>
    [Cmdlet(VerbsLifecycle.Invoke, "NtToken", DefaultParameterSetName = "FromToken")]
    [OutputType(typeof(object))]
    public sealed class InvokeNtTokenCmdlet : PSCmdlet
    {
        /// <summary>
        /// <para type="description">Specify the token to impersonate.</para>
        /// </summary>
        [Parameter(ParameterSetName = "FromToken", Position = 0, Mandatory = true)]
        public NtToken Token { get; set; }

        /// <summary>
        /// <para type="description">The script block to execute during impersonation.</para>
        /// </summary>
        [Parameter(Mandatory = true, Position = 1, ParameterSetName = "FromToken")]
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = "FromAnonymous")]
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = "FromCurrent")]
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = "FromSystem")]
        public ScriptBlock Script { get; set; }

        /// <summary>
        /// <para type="description">Specify to impersonate the current Token.</para>
        /// </summary>
        [Parameter(Mandatory = true, ParameterSetName = "FromCurrent")]
        public SwitchParameter Current { get; set; }

        /// <summary>
        /// <para type="description">Specify to impersonate a system Token. Must be an administrator.</para>
        /// </summary>
        [Parameter(Mandatory = true, ParameterSetName = "FromSystem")]
        public SwitchParameter System { get; set; }

        /// <summary>
        /// <para type="description">When the token is duplicated specify the impersonation level to use.</para>
        /// </summary>
        [Parameter(Position = 2, ParameterSetName = "FromToken")]
        [Parameter(ParameterSetName = "FromCurrent")]
        public SecurityImpersonationLevel ImpersonationLevel { get; set; }

        /// <summary>
        /// <para type="description">When the token is duplicated specify an Integrity Level to use.</para>
        /// </summary>
        [Parameter(ParameterSetName = "FromCurrent")]
        public TokenIntegrityLevel? IntegrityLevel { get; set; }

        /// <summary>
        /// <para type="description">Impersonate the anonymous token and run the script.</para>
        /// </summary>
        [Parameter(Mandatory = true, ParameterSetName = "FromAnonymous")]
        public SwitchParameter Anonymous { get; set; }

        /// <summary>
        /// <para type="description">Specify an object to pass to the script.</para>
        /// </summary>
        [Parameter(ValueFromPipeline = true)]
        public object InputObject { get; set; }

        /// <summary>
        /// Constructor.
        /// </summary>
        public InvokeNtTokenCmdlet()
        {
            ImpersonationLevel = SecurityImpersonationLevel.Impersonation;
        }

        private NtToken GetCurrentToken()
        {
            using (var token = NtToken.OpenProcessToken())
            {
                using (var new_token = token.DuplicateToken(ImpersonationLevel))
                {
                    if (IntegrityLevel.HasValue)
                    {
                        new_token.SetIntegrityLevel(IntegrityLevel.Value);
                    }
                    return new_token.Duplicate();
                }
            }
        }

        /// <summary>
        /// Overridden ProcessRecord method.
        /// </summary>
        protected override void ProcessRecord()
        {
            object obj = null;
            if (ParameterSetName == "FromToken")
            {
                if (Token.TokenType == TokenType.Impersonation && Token.ImpersonationLevel < ImpersonationLevel)
                {
                    throw new ArgumentException("Impersonation level can't be raised, specify an appropriate impersonation level");
                }

                obj = Token.RunUnderImpersonate(() => PSUtils.InvokeWithArg(Script, InputObject), ImpersonationLevel);
            }
            else if (ParameterSetName == "FromCurrent")
            {
                using (var token = GetCurrentToken())
                {
                    obj = token.RunUnderImpersonate(() => PSUtils.InvokeWithArg(Script, InputObject), ImpersonationLevel);
                }
            }
            else if (ParameterSetName == "FromSystem")
            {
                using (PSUtils.ImpersonateSystem())
                {
                    obj = PSUtils.InvokeWithArg(Script, InputObject);
                }
            }
            else
            {
                using (var imp = NtThread.Current.ImpersonateAnonymousToken())
                {
                    obj = PSUtils.InvokeWithArg(Script, InputObject);
                }
            }
            if (obj != null)
            {
                WriteObject(obj, true);
            }
        }
    }
}
