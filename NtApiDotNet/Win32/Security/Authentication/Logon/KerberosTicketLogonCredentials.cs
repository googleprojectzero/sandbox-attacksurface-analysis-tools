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
    /// Class to represent a KERB_TICKET_LOGON or a KERB_TICKET_UNLOCK_LOGON structure.
    /// </summary>
    public sealed class KerberosTicketLogonCredentials : ILsaLogonCredentials, ILsaLogonCredentialsSerializable
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

        /// <summary>
        /// If specified will create a KERB_TICKET_UNLOCK_LOGON credential buffer.
        /// </summary>
        public Luid? LogonId { get; set; }

        byte[] ILsaLogonCredentialsSerializable.ToArray()
        {
            using (var buffer = ToBuffer(true))
            {
                return buffer.ToArray();
            }
        }

        string ILsaLogonCredentials.AuthenticationPackage => AuthenticationPackage.KERBEROS_NAME;

        SafeBuffer ILsaLogonCredentials.ToBuffer(DisposableList list)
        {
            return ToBuffer(false);
        }

        private void PopulateLogon(LsaBufferBuilder<KERB_TICKET_LOGON> builder, bool relative)
        {
            builder.AddPointerBuffer(nameof(KERB_TICKET_LOGON.ServiceTicket),
                nameof(KERB_TICKET_LOGON.ServiceTicketLength), ServiceTicket.ToArray(), relative);
            builder.AddPointerBuffer(nameof(KERB_TICKET_LOGON.TicketGrantingTicket),
                nameof(KERB_TICKET_LOGON.TicketGrantingTicketLength), TicketGrantingTicket?.ToArray(), relative);
        }

        private SafeBufferGeneric ToBuffer(bool relative)
        {
            if (ServiceTicket is null)
            {
                throw new ArgumentNullException(nameof(ServiceTicket));
            }

            if (LogonId.HasValue)
            {
                var builder = new KERB_TICKET_UNLOCK_LOGON()
                {
                    LogonId = LogonId.Value
                }.ToBuilder();
                PopulateLogon(builder.GetSubBuilder(nameof(KERB_TICKET_UNLOCK_LOGON.Logon),
                    new KERB_TICKET_LOGON()
                    {
                        MessageType = KERB_LOGON_SUBMIT_TYPE.KerbTicketUnlockLogon,
                        Flags = (int)Flags
                    }), relative);
                return builder.ToBuffer();
            }
            else
            {
                var builder = new KERB_TICKET_LOGON()
                {
                    MessageType = KERB_LOGON_SUBMIT_TYPE.KerbTicketLogon,
                    Flags = (int)Flags
                }.ToBuilder();

                PopulateLogon(builder, relative);
                return builder.ToBuffer();
            }
        }
    }
}
