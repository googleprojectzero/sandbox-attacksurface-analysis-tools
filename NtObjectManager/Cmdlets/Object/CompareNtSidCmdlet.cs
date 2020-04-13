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
using System.Management.Automation;

namespace NtObjectManager.Cmdlets.Object
{
    /// <summary>
    /// <para type="synopsis">Compare two SIDs against various criteria.</para>
    /// <para type="description">This cmdlet compares two SIDs against various criteria. The default is to compare for equality,
    /// however you can test Integrity Level or Trust Level SIDs for which dominates.</para>
    /// </summary>
    /// <example>
    ///   <code>Compare-NtSid $sid1 $sid2</code>
    ///   <para>Checks both SIDs are equal.</para>
    /// </example>
    /// <example>
    ///   <code>Compare-NtSid (Get-NtSid -IntegrityLevel Low) $sid -Dominates</code>
    ///   <para>Checks if the left IL SID dominates the other.</para>
    /// </example>
    /// <example>
    ///   <code>Compare-NtSid (Get-NtSid -TrustType Protected -TrustLevel WinTcb) $sid -Dominate</code>
    ///   <para>Checks if the left Trust SID dominates the right.</para>
    /// </example>
    /// <example>
    ///   <code>Compare-NtSid $sid1 $sid2 -Prefix</code>
    ///   <para>Checks left SID is prefixed by the right. Note that both SIDs must be the same length, you probably want StartsWith.</para>
    /// </example>
    /// <example>
    ///   <code>Compare-NtSid $sid1 $sid2 -StartsWith</code>
    ///   <para>Checks left SID starts with the right. The right SID should be shorter than the left.</para>
    /// </example>
    [Cmdlet(VerbsData.Compare , "NtSid", DefaultParameterSetName = "EqualSid")]
    [OutputType(typeof(bool))]
    public class CompareNtSidCmdlet : PSCmdlet
    {
        /// <summary>
        /// <para type="description">Specify the left SID to compare.</para>
        /// </summary>
        [Parameter(Position = 0, Mandatory = true)]
        public Sid Left { get; set; }

        /// <summary>
        /// <para type="description">Specify the right SID to compare.</para>
        /// </summary>
        [Parameter(Position = 1, Mandatory = true)]
        public Sid Right { get; set; }

        /// <summary>
        /// <para type="description">Check if the left SID dominates the right. Supports IL or Trust Level SIDs.</para>
        /// </summary>
        [Parameter(Position = 0, Mandatory = true, ParameterSetName = "DominateSid")]
        public SwitchParameter Dominates { get; set; }

        /// <summary>
        /// <para type="description">Check if prefix of one SID matches another.</para>
        /// </summary>
        [Parameter(Position = 0, Mandatory = true, ParameterSetName = "PrefixSid")]
        public SwitchParameter Prefix { get; set; }

        /// <summary>
        /// <para type="description">Check if one SID starts with another.</para>
        /// </summary>
        [Parameter(Position = 0, Mandatory = true, ParameterSetName = "StartsWithSid")]
        public SwitchParameter StartsWith { get; set; }

        /// <summary>
        /// Process record.
        /// </summary>
        protected override void ProcessRecord()
        {
            switch (ParameterSetName)
            {
                case "EqualSid":
                    WriteObject(Left.Equals(Right));
                    break;
                case "DominateSid":
                    CheckDominateSid();
                    break;
                case "PrefixSid":
                    WriteObject(Left.EqualPrefix(Right));
                    break;
                case "StartsWithSid":
                    WriteObject(Left.StartsWith(Right));
                    break;
            }
        }

        private void CheckDominateSid()
        {
            if (NtSecurity.IsIntegritySid(Left))
            {
                WriteObject(Left.Dominates(Right));
            }
            else if (NtSecurity.IsProcessTrustSid(Left))
            {
                WriteObject(Left.DominatesForTrust(Right));
            }
        }
    }
}
