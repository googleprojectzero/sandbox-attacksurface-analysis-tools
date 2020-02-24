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
using System.Collections.Generic;
using System.Linq;

namespace NtObjectManager.Cmdlets.Accessible
{
    /// <summary>
    /// Information about a token.
    /// </summary>
    public sealed class TokenInformation
    {
        /// <summary>
        /// Token user.
        /// </summary>
        public Sid User { get; }

        /// <summary>
        /// Token user name.
        /// </summary>
        public string UserName => User.Name;

        /// <summary>
        /// Token integrity level
        /// </summary>
        public TokenIntegrityLevel IntegrityLevel { get; }

        /// <summary>
        /// Token type
        /// </summary>
        public TokenType TokenType { get; }

        /// <summary>
        /// Token impersonation level
        /// </summary>
        public SecurityImpersonationLevel ImpersonationLevel { get; }

        /// <summary>
        /// Token ID
        /// </summary>
        public Luid TokenId { get; }

        /// <summary>
        /// Elevated token
        /// </summary>
        public bool Elevated { get; }

        /// <summary>
        /// Restricted token
        /// </summary>
        public bool Restricted { get; }

        /// <summary>
        /// Write restricted token
        /// </summary>
        public bool WriteRestricted { get; }

        /// <summary>
        /// App container token
        /// </summary>
        public bool AppContainer { get; }

        /// <summary>
        /// App container SID (if an AppContainer)
        /// </summary>
        public Sid AppContainerSid { get; }

        /// <summary>
        /// Low privilege AC
        /// </summary>
        public bool LowPrivilegeAppContainer { get; }

        /// <summary>
        /// The session ID of the token.
        /// </summary>
        public int SessionId { get; }

        /// <summary>
        /// Get token groups.
        /// </summary>
        public IEnumerable<UserGroup> Groups { get; }

        /// <summary>
        /// Get restricted SIDs.
        /// </summary>
        public IEnumerable<UserGroup> RestrictedSids { get; }

        /// <summary>
        /// Get capability SIDs.
        /// </summary>
        public IEnumerable<UserGroup> Capabilities { get; }

        /// <summary>
        /// Additonal information of where the token was sourced from
        /// </summary>
        public Dictionary<string, object> SourceData { get; }

        /// <summary>
        /// Overridden ToString.
        /// </summary>
        /// <returns></returns>
        public override string ToString()
        {
            return $"User: {User}";
        }

        internal TokenInformation(NtToken token) : this(token, null)
        {
        }

        internal TokenInformation(NtToken token, NtProcess process)
        {
            SourceData = new Dictionary<string, object>();
            TokenId = token.Id;
            User = token.User.Sid;
            IntegrityLevel = token.IntegrityLevel;
            TokenType = token.TokenType;
            ImpersonationLevel = token.ImpersonationLevel;
            AppContainer = token.AppContainer;
            AppContainerSid = token.AppContainerSid;
            Elevated = token.Elevated;
            Restricted = token.Restricted;
            WriteRestricted = token.WriteRestricted;
            LowPrivilegeAppContainer = token.LowPrivilegeAppContainer;
            SessionId = token.SessionId;
            Groups = token.Groups.ToList().AsReadOnly();
            RestrictedSids = token.RestrictedSids.ToList().AsReadOnly();
            Capabilities = token.Capabilities.ToList().AsReadOnly();

            if (process != null)
            {
                SourceData["ProcessId"] = process.ProcessId;
                SourceData["Name"] = process.Name;
                SourceData["ImagePath"] = process.GetImageFilePath(false);
                SourceData["CommandLine"] = process.CommandLine;
            }
        }
    }
}