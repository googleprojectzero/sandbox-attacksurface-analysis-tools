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

using System;

namespace NtApiDotNet.Net.Firewall
{
    /// <summary>
    /// Class to prepresent a key manager.
    /// </summary>
    public sealed class IPsecKeyManager
    {
        /// <summary>
        /// The manager's key.
        /// </summary>
        public Guid Key { get; }
        /// <summary>
        /// The manager's name.
        /// </summary>
        public string Name { get; }
        /// <summary>
        /// The manager's description.
        /// </summary>
        public string Description { get; }
        /// <summary>
        /// The manager's flags.
        /// </summary>
        public IPsecKeyManagerFlags Flags { get; }
        /// <summary>
        /// The manager's dictation timeout hint.
        /// </summary>
        public int KeyDictationTimeoutHint { get; }

        internal IPsecKeyManager(IPSEC_KEY_MANAGER0 key_manager)
        {
            Key = key_manager.keyManagerKey;
            Name = key_manager.displayData.name ?? string.Empty;
            Description = key_manager.displayData.description ?? string.Empty;
            Flags = key_manager.flags;
            KeyDictationTimeoutHint = key_manager.keyDictationTimeoutHint;
        }
    }
}
