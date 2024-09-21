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
    /// Class to represent a firewall session.
    /// </summary>
    public sealed class FirewallSession
    {
        /// <summary>
        /// The session key.
        /// </summary>
        public Guid SessionKey { get; }

        /// <summary>
        /// Name of the session.
        /// </summary>
        public string Name { get; }

        /// <summary>
        /// Description of the session.
        /// </summary>
        public string Description { get; }

        /// <summary>
        /// Session flags.
        /// </summary>
        public FirewallSessionFlags Flags { get; }

        /// <summary>
        /// Transaction wait timeout in ms.
        /// </summary>
        public int TxnWaitTimeoutInMSec { get; }

        /// <summary>
        /// The process ID of the session owner.
        /// </summary>
        public int ProcessId { get; }

        /// <summary>
        /// The user SID of the owner.
        /// </summary>
        public Sid Sid { get; }

        /// <summary>
        /// The name of the owner.
        /// </summary>
        public string UserName { get; }

        /// <summary>
        /// Is session kernel mode.
        /// </summary>
        public bool KernelMode { get; }

        /// <summary>
        /// Constructor. Used when opening a session.
        /// </summary>
        /// <param name="name">The name of the session.</param>
        /// <param name="description">The description of the sesion.</param>
        /// <param name="flags">Session flags.</param>
        /// <param name="txn_wait_timeout_ms">Transaction timeout in ms.</param>
        public FirewallSession(string name, string description, FirewallSessionFlags flags, int txn_wait_timeout_ms)
        {
            Name = name ?? string.Empty;
            Description = description ?? string.Empty;
            Flags = flags;
            TxnWaitTimeoutInMSec = txn_wait_timeout_ms;
            UserName = string.Empty;
        }

        /// <summary>
        /// Constructor. Used when opening a session.
        /// </summary>
        /// <param name="flags">Session flags.</param>
        public FirewallSession(FirewallSessionFlags flags) 
            : this(string.Empty, string.Empty, flags, 0)
        {
        }

        internal FirewallSession(FWPM_SESSION0 session)
        {
            SessionKey = session.sessionKey;
            Name = string.IsNullOrEmpty(session.displayData.name) ? SessionKey.ToString() : session.displayData.name;
            Description = session.displayData.description ?? string.Empty;
            Flags = session.flags;
            TxnWaitTimeoutInMSec = session.txnWaitTimeoutInMSec;
            ProcessId = session.processId;
            Sid = Sid.Parse(session.sid, false).GetResultOrDefault();
            UserName = session.username ?? string.Empty;
            KernelMode = session.kernelMode;
        }

        internal FWPM_SESSION0 ToStruct(DisposableList list)
        {
            FWPM_SESSION0 session = new FWPM_SESSION0();
            session.displayData.name = Name;
            session.displayData.description = Description;
            session.flags = Flags;
            session.txnWaitTimeoutInMSec = TxnWaitTimeoutInMSec;
            return session;
        }
    }
}
