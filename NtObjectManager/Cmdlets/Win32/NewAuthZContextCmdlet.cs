//  Copyright 2020 Google Inc. All Rights Reserved.
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
using NtApiDotNet.Win32.Security.Authorization;
using System.Management.Automation;

namespace NtObjectManager.Cmdlets.Win32
{
    /// <summary>
    /// <para type="synopsis">Create a new AuthZ Client Context..</para>
    /// <para type="description">This cmdlet creates a new AuthZ Client Context.</para>
    /// </summary>
    /// <example>
    ///   <code>New-AuthZContext -ResourceManager $rm -Token $token</code>
    ///   <para>Create a new AuthZ Client Context from a Resource Manager and Token.</para>
    /// </example>
    [Cmdlet(VerbsCommon.New, "AuthZContext", DefaultParameterSetName = "FromToken")]
    [OutputType(typeof(AuthZContext))]
    public class NewAuthZContextCmdlet : PSCmdlet
    {
        /// <summary>
        /// <para type="description">Specify the Resource Manager.</para>
        /// </summary>
        [Parameter(Position = 0, Mandatory = true)]
        public AuthZResourceManager ResourceManager { get; set; }

        /// <summary>
        /// <para type="description">Specify the Token to base the Client Context.</para>
        /// </summary>
        [Parameter(Position = 1, ParameterSetName = "FromToken")]
        public NtToken Token { get; set; }

        private NtToken GetToken()
        {
            if (Token != null)
            {
                return Token.DuplicateToken(TokenType.Impersonation,
                    SecurityImpersonationLevel.Identification,TokenAccessRights.Query);
            }
            else
            {
                using (NtToken token = NtToken.OpenEffectiveToken())
                {
                    return token.DuplicateToken(TokenType.Impersonation,
                        SecurityImpersonationLevel.Identification, TokenAccessRights.Query);
                }
            }
        }

        /// <summary>
        /// Process Record.
        /// </summary>
        protected override void ProcessRecord()
        {
            switch (ParameterSetName)
            {
                case "FromToken":
                    WriteObject(ResourceManager.CreateContext(GetToken()));
                    break;
            }
        }
    }
}
