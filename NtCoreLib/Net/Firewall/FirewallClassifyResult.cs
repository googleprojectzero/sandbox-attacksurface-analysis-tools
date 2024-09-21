//  Copyright 2021 Google LLC. All Rights Reserved.
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

namespace NtApiDotNet.Net.Firewall
{
    /// <summary>
    /// Class to represet the result of a classify operations.
    /// </summary>
    public sealed class FirewallClassifyResult
    {
        /// <summary>
        /// Action type of the classify result.
        /// </summary>
        public FirewallActionType ActionType { get; }
        /// <summary>
        /// Internal context.
        /// </summary>
        public ulong OutContext { get; }
        /// <summary>
        /// ID of the filter.
        /// </summary>
        public ulong FilterId { get; }
        /// <summary>
        /// Associated rights.
        /// </summary>
        public FirewallRightActions Rights { get; }
        /// <summary>
        /// Classify flags.
        /// </summary>
        public FirewallClassifyOutFlags Flags { get; }

        internal FirewallClassifyResult(FWPS_CLASSIFY_OUT0 result)
        {
            ActionType = result.actionType;
            OutContext = result.outContext;
            FilterId = result.filterId;
            Rights = result.rights;
            Flags = result.flags;
        }
    }
}
