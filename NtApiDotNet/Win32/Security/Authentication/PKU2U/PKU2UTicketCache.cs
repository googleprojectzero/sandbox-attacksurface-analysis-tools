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

using NtApiDotNet.Win32.Security.Authentication.Kerberos;
using System.Collections.Generic;

namespace NtApiDotNet.Win32.Security.Authentication.PKU2U
{
    /// <summary>
    /// Class to query the PKU2U Ticket Cache from LSASS.
    /// </summary>
    public static class PKU2UTicketCache
    {
        /// <summary>
        /// Query Kerberos Ticket cache information.
        /// </summary>
        /// <param name="logon_id">The Logon Session ID to query.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The list of cached tickets.</returns>
        /// <remarks>This doesn't query the tickets themselves.</remarks>
        public static NtResult<IEnumerable<KerberosTicketCacheInfo>> QueryTicketCacheInfo(Luid logon_id, bool throw_on_error)
        {
            return KerberosTicketCache.QueryTicketCacheInfo(AuthenticationPackage.PKU2U_NAME, logon_id, throw_on_error);
        }

        /// <summary>
        /// Query Kerberos Ticket cache information.
        /// </summary>
        /// <param name="logon_id">The Logon Session ID to query.</param>
        /// <returns>The list of cached tickets.</returns>
        /// <remarks>This doesn't query the tickets themselves.</remarks>
        public static IEnumerable<KerberosTicketCacheInfo> QueryTicketCacheInfo(Luid logon_id)
        {
            return QueryTicketCacheInfo(logon_id, true).Result;
        }

        /// <summary>
        /// Query Kerberos Ticket cache information.
        /// </summary>
        /// <returns>The list of cached tickets.</returns>
        /// <remarks>This doesn't query the tickets themselves.</remarks>
        public static IEnumerable<KerberosTicketCacheInfo> QueryTicketCacheInfo()
        {
            return QueryTicketCacheInfo(Luid.Empty);
        }

        /// <summary>
        /// Purge the ticket cache.
        /// </summary>
        /// <param name="purge_all_tickets">Purge all tickets.</param>
        /// <param name="logon_id">The Logon Session ID to purge.</param>
        /// <param name="ticket_template">Ticket template to purge.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public static NtStatus PurgeTicketCacheEx(bool purge_all_tickets, Luid logon_id, KerberosTicketCacheInfo ticket_template, bool throw_on_error)
        {
            return KerberosTicketCache.PurgeTicketCacheEx(AuthenticationPackage.PKU2U_NAME, 
                purge_all_tickets, logon_id, ticket_template, throw_on_error);
        }

        /// <summary>
        /// Purge the ticket cache.
        /// </summary>
        /// <param name="purge_all_tickets">Purge all tickets.</param>
        /// <param name="logon_id">The Logon Session ID to purge.</param>
        /// <param name="ticket_template">Ticket template to purge.</param>
        public static void PurgeTicketCacheEx(bool purge_all_tickets, Luid logon_id, KerberosTicketCacheInfo ticket_template)
        {
            PurgeTicketCacheEx(purge_all_tickets, logon_id, ticket_template, true);
        }
    }
}
