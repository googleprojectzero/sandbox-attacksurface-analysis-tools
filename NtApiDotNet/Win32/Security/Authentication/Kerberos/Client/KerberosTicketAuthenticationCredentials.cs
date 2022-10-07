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
    /// Kerberos authentication credentials to use a ticket.
    /// </summary>
    public sealed class KerberosTicketAuthenticationCredentials : AuthenticationCredentials, IKerberosAuthenticationCredentials
    {
        /// <summary>
        /// The kerberos ticket to use.
        /// </summary>
        public KerberosExternalTicket Ticket { get; set; }

        /// <summary>
        /// Constructor.
        /// </summary>
        public KerberosTicketAuthenticationCredentials() : base(true)
        {
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="ticket">The kerberos ticket to use.</param>
        public KerberosTicketAuthenticationCredentials(KerberosExternalTicket ticket)
            : this()
        {
            Ticket = ticket;
        }

        internal override SafeBuffer ToBuffer(DisposableList list, string package)
        {
            throw new NotImplementedException();
        }
    }
}
