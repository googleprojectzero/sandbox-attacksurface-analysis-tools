//  Copyright 2022 Google LLC. All Rights Reserved.
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
using System.Runtime.InteropServices;

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos.Client
{
    /// <summary>
    /// Kerberos authentication credentials to use a ticket cache.
    /// </summary>
    public sealed class KerberosTicketCacheAuthenticationCredentials : AuthenticationCredentials, IKerberosAuthenticationCredentials
    {
        /// <summary>
        /// The local ticket cache.
        /// </summary>
        public KerberosLocalTicketCache TicketCache { get; set; }

        /// <summary>
        /// Specify a ticket to encrypt to.
        /// </summary>
        public KerberosTicket SessionKeyTicket { get; set; }

        /// <summary>
        /// Constructor.
        /// </summary>
        public KerberosTicketCacheAuthenticationCredentials() : base(true)
        {
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="ticket_cache">The kerberos ticket cache.</param>
        /// <param name="session_key_ticket">The session key ticket.</param>
        public KerberosTicketCacheAuthenticationCredentials(KerberosLocalTicketCache ticket_cache, KerberosTicket session_key_ticket = null) 
            : this()
        {
            TicketCache = ticket_cache;
            SessionKeyTicket = session_key_ticket;
        }

        internal override SafeBuffer ToBuffer(DisposableList list, string package)
        {
            throw new NotImplementedException();
        }

        internal KerberosExternalTicket GetTicket(string target)
        {
            if (SessionKeyTicket is null)
            {
                return TicketCache?.GetTicket(target);
            }
            return TicketCache?.GetTicket(target, SessionKeyTicket);
        }
    }
}
