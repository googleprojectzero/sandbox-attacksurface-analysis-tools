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

using NtApiDotNet.Utilities.Reflection;
using NtApiDotNet.Win32.Security.Authentication.Kerberos;
using NtApiDotNet.Win32.Security.Native;
using System;
using System.Runtime.InteropServices;

namespace NtApiDotNet.Win32.Security.Authentication.Logon
{
    /// <summary>
    /// Flags for ticket logon.
    /// </summary>
    [Flags]
    public enum KerberosTicketLogonFlags
    {
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
        None = 0,
        [SDKName("KERB_LOGON_FLAG_ALLOW_EXPIRED_TICKET")]
        AllowExpiredTicket = 1,
        [SDKName("KERB_LOGON_FLAG_REDIRECTED")]
        Redirected = 2,
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
    }

    /// <summary>
    /// Class to represent a KERB_TICKET_LOGON structure.
    /// </summary>
    public sealed class KerberosTicketLogonCredentials : ILogonCredentials
    {
        /// <summary>
        /// The Kerberos service ticket.
        /// </summary>
        public KerberosTicket ServiceTicket { get; set; }

        /// <summary>
        /// The optional TGT credentials.
        /// </summary>
        public KerberosCredential TicketGrantingTicket { get; set; }

        /// <summary>
        /// The kerberos logon ticket flags.
        /// </summary>
        public KerberosTicketLogonFlags Flags { get; set; }

        SafeBuffer ILogonCredentials.ToBuffer(DisposableList list)
        {
            if (ServiceTicket is null)
            {
                throw new ArgumentNullException(nameof(ServiceTicket));
            }

            var builder = new KERB_TICKET_LOGON()
            {
                MessageType = KERB_LOGON_SUBMIT_TYPE.KerbTicketLogon,
                Flags = (int)Flags
            }.ToBuilder();

            builder.AddPointerBuffer(nameof(KERB_TICKET_LOGON.ServiceTicket), 
                nameof(KERB_TICKET_LOGON.ServiceTicketLength), ServiceTicket.ToArray());
            builder.AddPointerBuffer(nameof(KERB_TICKET_LOGON.TicketGrantingTicket), 
                nameof(KERB_TICKET_LOGON.TicketGrantingTicketLength), TicketGrantingTicket?.ToArray());

            return builder.ToBuffer();
        }
    }
}
