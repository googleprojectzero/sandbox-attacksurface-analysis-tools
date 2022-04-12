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

using NtApiDotNet.Win32.SafeHandles;
using NtApiDotNet.Win32.Security.Native;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos
{
    /// <summary>
    /// Class to query the Kerberos Ticket Cache from LSASS.
    /// </summary>
    public static class KerberosTicketCache 
    {
        internal static int CalculateLength(params string[] strs)
        {
            int ret = 0;
            foreach (var s in strs)
            {
                ret += CalculateLength(s?.Length);
            }
            return ret;
        }

        internal static int CalculateLength(int? length)
        {
            int ret = length ?? 0;
            return (ret + 1) * 2;
        }

        internal static UnicodeStringOut MarshalString(SafeBuffer buffer, BinaryWriter writer, byte[] value)
        {
            var ret = new UnicodeStringOut();
            if (value != null)
            {
                ret.Length = (ushort)value.Length;
                ret.MaximumLength = (ushort)(ret.Length + 2);
                ret.Buffer = buffer.DangerousGetHandle() + (int)writer.BaseStream.Position;
                writer.Write(value);
            }
            writer.Write((ushort)0);
            return ret;
        }

        internal static UnicodeStringOut MarshalString(SafeBuffer buffer, BinaryWriter writer, string value)
        {
            return MarshalString(buffer, writer, value != null ? Encoding.Unicode.GetBytes(value) : null);
        }

        internal static NtResult<LsaCallPackageResponse> CallPackage(SafeLsaLogonHandle handle, SafeBuffer buffer, bool throw_on_error)
        {
            var package = handle.LookupAuthPackage(AuthenticationPackage.KERBEROS_NAME, throw_on_error);
            if (!package.IsSuccess)
                return package.Cast<LsaCallPackageResponse>();
            return handle.CallPackage(package.Result, buffer, throw_on_error);
        }

        private static NtResult<KerberosTicketCacheInfo[]> QueryTicketCacheList<T>(KERB_PROTOCOL_MESSAGE_TYPE query_type, 
            SafeLsaLogonHandle handle, Luid logon_id, Func<T, KerberosTicketCacheInfo> map_fn, bool throw_on_error) where T : struct
        {
            var request_struct = new KERB_QUERY_TKT_CACHE_REQUEST()
            {
                LogonId = logon_id,
                MessageType = query_type
            };
            using (var request = request_struct.ToBuffer())
            {
                using (var result = CallPackage(handle, request, throw_on_error))
                {
                    if (!result.IsSuccess)
                        return result.Cast<KerberosTicketCacheInfo[]>();
                    if (!result.Result.Status.IsSuccess())
                        return result.Result.Status.CreateResultFromError<KerberosTicketCacheInfo[]>(throw_on_error);
                    var response = result.Result.Buffer.Read<KERB_QUERY_TKT_CACHE_RESPONSE_HEADER>(0);
                    if (response.CountOfTickets == 0)
                        return new KerberosTicketCacheInfo[0].CreateResult();
                    var buffer = BufferUtils.GetStructAtOffset<KERB_QUERY_TKT_CACHE_RESPONSE>(result.Result.Buffer, 0);
                    T[] infos = new T[response.CountOfTickets];
                    buffer.Data.ReadArray(0, infos, 0, response.CountOfTickets);
                    return infos.Select(map_fn).ToArray().CreateResult();
                }
            }
        }

        private static NtResult<KerberosTicketCacheInfo[]> QueryTicketCacheList(SafeLsaLogonHandle handle, Luid logon_id, bool throw_on_error)
        {
            var ret = QueryTicketCacheList<KERB_TICKET_CACHE_INFO_EX3>(KERB_PROTOCOL_MESSAGE_TYPE.KerbQueryTicketCacheEx3Message,
                handle, logon_id, t => new KerberosTicketCacheInfo(t), false);
            if (ret.IsSuccess)
                return ret;
            return QueryTicketCacheList<KERB_TICKET_CACHE_INFO_EX2>(KERB_PROTOCOL_MESSAGE_TYPE.KerbQueryTicketCacheEx2Message,
                handle, logon_id, t => new KerberosTicketCacheInfo(t), throw_on_error);
        }

        private static NtResult<SafeLsaReturnBufferHandle> QueryCachedTicketBuffer(SafeLsaLogonHandle handle, string target_name, KerberosRetrieveTicketFlags flags,
            Luid logon_id, SecHandle sec_handle, KerberosTicketFlags ticket_flags, KerberosEncryptionType encryption_type, bool throw_on_error)
        {
            int string_length = (target_name.Length) * 2;
            int max_string_length = string_length + 2;
            using (var request = new SafeStructureInOutBuffer<KERB_RETRIEVE_TKT_REQUEST>(max_string_length, true))
            {
                request.Data.WriteUnicodeString(target_name + '\0');
                var request_str = new KERB_RETRIEVE_TKT_REQUEST()
                {
                    CacheOptions = flags,
                    CredentialsHandle = sec_handle,
                    LogonId = logon_id,
                    MessageType = KERB_PROTOCOL_MESSAGE_TYPE.KerbRetrieveEncodedTicketMessage,
                    TicketFlags = ((uint)ticket_flags).RotateBits(),
                    EncryptionType = encryption_type,
                    TargetName = new UnicodeStringOut()
                    {
                        Length = (ushort)string_length,
                        MaximumLength = (ushort)max_string_length,
                        Buffer = request.Data.DangerousGetHandle()
                    }
                };
                request.Result = request_str;
                using (var result = CallPackage(handle, request, throw_on_error))
                {
                    if (!result.IsSuccess)
                        return result.Cast<SafeLsaReturnBufferHandle>();
                    if (!result.Result.Status.IsSuccess())
                        return result.Result.Status.CreateResultFromError<SafeLsaReturnBufferHandle>(throw_on_error);
                    return result.Result.Buffer.Detach().CreateResult();
                }
            }
        }

        private static NtResult<KerberosExternalTicket> QueryCachedTicket(SafeLsaLogonHandle handle, string target_name, KerberosRetrieveTicketFlags flags,
            Luid logon_id, SecHandle sec_handle, KerberosTicketFlags ticket_flags, KerberosEncryptionType encryption_type, bool throw_on_error)
        {
            using (var buffer = QueryCachedTicketBuffer(handle, target_name, flags, logon_id, sec_handle, ticket_flags, encryption_type, throw_on_error))
            {
                if (!buffer.IsSuccess)
                    return buffer.Cast<KerberosExternalTicket>();

                KERB_EXTERNAL_TICKET ticket = buffer.Result.Read<KERB_EXTERNAL_TICKET>(0);
                if (!KerberosExternalTicket.TryParse(ticket, flags.HasFlagSet(KerberosRetrieveTicketFlags.AsKerbCred), out KerberosExternalTicket ret))
                    return NtStatus.STATUS_INVALID_PARAMETER.CreateResultFromError<KerberosExternalTicket>(throw_on_error);
                return ret.CreateResult();
            }
        }

        /// <summary>
        /// Retrieve a Kerberos Ticket.
        /// </summary>
        /// <param name="target_name">The target service for the Ticket.</param>
        /// <param name="logon_id">The Logon Session ID to query.</param>
        /// <param name="cred_handle">Optional credential handle.</param>
        /// <param name="flags">Flags for retrieving the ticket.</param>
        /// <param name="ticket_flags">Ticket flags for the ticket.</param>
        /// <param name="encryption_type">Encryption type.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The Kerberos Ticket.</returns>
        public static NtResult<KerberosExternalTicket> RetrieveTicket(string target_name, Luid logon_id, 
            CredentialHandle cred_handle, KerberosRetrieveTicketFlags flags, KerberosTicketFlags ticket_flags,
            KerberosEncryptionType encryption_type, bool throw_on_error)
        {
            using (var handle = SafeLsaLogonHandle.Connect(throw_on_error))
            {
                if (!handle.IsSuccess)
                    return handle.Cast<KerberosExternalTicket>();
                return QueryCachedTicket(handle.Result, target_name, flags,
                    logon_id, cred_handle?.CredHandle ?? new SecHandle(), 
                    ticket_flags, encryption_type, throw_on_error);
            }
        }

        /// <summary>
        /// Retrieve a Kerberos Ticket.
        /// </summary>
        /// <param name="target_name">The target service for the Ticket.</param>
        /// <param name="logon_id">The Logon Session ID to query.</param>
        /// <param name="cred_handle">Optional credential handle.</param>
        /// <param name="flags">Flags for retrieving the ticket.</param>
        /// <param name="ticket_flags">Ticket flags for the ticket.</param>
        /// <param name="encryption_type">Encryption type.</param>
        /// <returns>The Kerberos Ticket.</returns>
        public static KerberosExternalTicket RetrieveTicket(string target_name, Luid logon_id,
            CredentialHandle cred_handle, KerberosRetrieveTicketFlags flags, KerberosTicketFlags ticket_flags,
            KerberosEncryptionType encryption_type)
        {
            return RetrieveTicket(target_name, logon_id, cred_handle, flags, ticket_flags, encryption_type, true).Result;
        }

        /// <summary>
        /// Get a Kerberos Ticket.
        /// </summary>
        /// <param name="target_name">The target service for the Ticket.</param>
        /// <param name="logon_id">The Logon Session ID to query.</param>
        /// <param name="cached_only">True to only query for cached tickets.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The Kerberos Ticket.</returns>
        public static NtResult<KerberosExternalTicket> GetTicket(string target_name, Luid logon_id, bool cached_only, bool throw_on_error)
        {
            KerberosRetrieveTicketFlags flags = cached_only ? KerberosRetrieveTicketFlags.UseCacheOnly : KerberosRetrieveTicketFlags.Default;
            flags |= KerberosRetrieveTicketFlags.AsKerbCred;
            return RetrieveTicket(target_name, logon_id, null, flags, KerberosTicketFlags.None, KerberosEncryptionType.NULL, throw_on_error);
        }

        /// <summary>
        /// Get a Kerberos Ticket.
        /// </summary>
        /// <param name="target_name">The target service for the Ticket.</param>
        /// <param name="logon_id">The Logon Session ID to query.</param>
        /// <param name="cached_only">True to only query for cached tickets.</param>
        /// <returns>The Kerberos Ticket.</returns>
        public static KerberosExternalTicket GetTicket(string target_name, Luid logon_id, bool cached_only)
        {
            return GetTicket(target_name, logon_id, cached_only, true).Result;
        }

        /// <summary>
        /// Get a Kerberos Ticket.
        /// </summary>
        /// <param name="target_name">The target service for the Ticket.</param>
        /// <param name="logon_id">The Logon Session ID to query.</param>
        /// <returns>The Kerberos Ticket.</returns>
        public static KerberosExternalTicket GetTicket(string target_name, Luid logon_id)
        {
            return GetTicket(target_name, logon_id, false, true).Result;
        }

        /// <summary>
        /// Get a Kerberos Ticket.
        /// </summary>
        /// <param name="target_name">The target service for the Ticket.</param>
        /// <param name="cached_only">True to only query for cached tickets.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The Kerberos Ticket.</returns>
        [Obsolete("Use GetTicket with explicit logon_id parameter.")]
        public static NtResult<KerberosExternalTicket> GetTicket(string target_name, bool cached_only, bool throw_on_error)
        {
            return GetTicket(target_name, NtToken.PseudoEffectiveToken.AuthenticationId, cached_only, throw_on_error);
        }

        /// <summary>
        /// Get a Kerberos Ticket.
        /// </summary>
        /// <param name="target_name">The target service for the Ticket.</param>
        /// <param name="cached_only">True to only query for cached tickets.</param>
        /// <returns>The Kerberos Ticket.</returns>
        [Obsolete("Use GetTicket with explicit logon_id parameter.")]
        public static KerberosExternalTicket GetTicket(string target_name, bool cached_only)
        {
            return GetTicket(target_name, cached_only, true).Result;
        }

        /// <summary>
        /// Get a Kerberos Ticket.
        /// </summary>
        /// <param name="target_name">The target service for the Ticket.</param>
        /// <returns>The Kerberos Ticket.</returns>
        [Obsolete("Use GetTicket with explicit logon_id parameter.")]
        public static KerberosExternalTicket GetTicket(string target_name)
        {
            return GetTicket(target_name, false);
        }

        /// <summary>
        /// Get a Kerberos Ticket from a credential handle.
        /// </summary>
        /// <param name="target_name">The target service for the Ticket.</param>
        /// <param name="credential_handle">The credential handle to query.</param>
        /// <param name="cached_only">True to only query for cached tickets.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The Kerberos Ticket.</returns>
        public static NtResult<KerberosExternalTicket> GetTicket(string target_name, CredentialHandle credential_handle, bool cached_only, bool throw_on_error)
        {
            KerberosRetrieveTicketFlags flags = cached_only ? KerberosRetrieveTicketFlags.UseCacheOnly : KerberosRetrieveTicketFlags.Default;
            flags |= KerberosRetrieveTicketFlags.AsKerbCred | KerberosRetrieveTicketFlags.UseCredHandle;
            return RetrieveTicket(target_name, default, credential_handle, flags, KerberosTicketFlags.None, KerberosEncryptionType.NULL, throw_on_error);
        }

        /// <summary>
        /// Get a Kerberos Ticket from a credential handle.
        /// </summary>
        /// <param name="target_name">The target service for the Ticket.</param>
        /// <param name="credential_handle">The credential handle to query.</param>
        /// <param name="cached_only">True to only query for cached tickets.</param>
        /// <returns>The Kerberos Ticket.</returns>
        public static KerberosExternalTicket GetTicket(string target_name, CredentialHandle credential_handle, bool cached_only)
        {
            return GetTicket(target_name, credential_handle, cached_only, true).Result;
        }

        /// <summary>
        /// Get a Kerberos Ticket from a credential handle.
        /// </summary>
        /// <param name="target_name">The target service for the Ticket.</param>
        /// <param name="credential_handle">The credential handle to query.</param>
        /// <returns>The Kerberos Ticket.</returns>
        public static KerberosExternalTicket GetTicket(string target_name, CredentialHandle credential_handle)
        {
            return GetTicket(target_name, credential_handle, false, true).Result;
        }

        /// <summary>
        /// Query Kerberos Ticket cache.
        /// </summary>
        /// <param name="logon_id">The Logon Session ID to query.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The list of cached tickets.</returns>
        public static NtResult<KerberosExternalTicket[]> QueryTicketCache(Luid logon_id, bool throw_on_error)
        {
            using (var handle = SafeLsaLogonHandle.Connect(throw_on_error))
            {
                if (!handle.IsSuccess)
                    return handle.Cast<KerberosExternalTicket[]>();
                var list = QueryTicketCacheList(handle.Result, logon_id, throw_on_error);
                if (!list.IsSuccess)
                    return list.Cast<KerberosExternalTicket[]>();

                var tickets = new List<KerberosExternalTicket>();
                foreach (var info in list.Result)
                {
                    var ticket = QueryCachedTicket(handle.Result, $"{info.ServerName}@{info.ServerRealm}",
                        KerberosRetrieveTicketFlags.UseCacheOnly | KerberosRetrieveTicketFlags.AsKerbCred,
                        logon_id, new SecHandle(), KerberosTicketFlags.None, KerberosEncryptionType.NULL, false);
                    if (ticket.IsSuccess)
                    {
                        tickets.Add(ticket.Result);
                    }
                }
                return tickets.ToArray().CreateResult();
            }
        }

        /// <summary>
        /// Query Kerberos Ticket cache.
        /// </summary>
        /// <param name="logon_id">The Logon Session ID to query.</param>
        /// <returns>The list of cached tickets.</returns>
        public static KerberosExternalTicket[] QueryTicketCache(Luid logon_id)
        {
            return QueryTicketCache(logon_id, true).Result;
        }

        /// <summary>
        /// Query Kerberos Ticket cache for the current logon session.
        /// </summary>
        /// <returns>The list of cached tickets.</returns>
        public static KerberosExternalTicket[] QueryTicketCache()
        {
            return QueryTicketCache(new Luid());
        }

        /// <summary>
        /// Query Kerberos Ticket cache information.
        /// </summary>
        /// <param name="logon_id">The Logon Session ID to query.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The list of cached tickets.</returns>
        /// <remarks>This doesn't query the tickets themselves.</remarks>
        public static NtResult<IEnumerable<KerberosTicketCacheInfo>> QueryTicketCacheInfo(Luid logon_id, bool throw_on_error)
        {
            using (var handle = SafeLsaLogonHandle.Connect(throw_on_error))
            {
                if (!handle.IsSuccess)
                    return handle.Cast<IEnumerable<KerberosTicketCacheInfo>>();
                return QueryTicketCacheList(handle.Result, logon_id, throw_on_error).Cast<IEnumerable<KerberosTicketCacheInfo>>();
            }
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
            return QueryTicketCacheInfo(new Luid());
        }

        /// <summary>
        /// Query for the TGT for a logon session.
        /// </summary>
        /// <param name="logon_id">The logon session ID. Specify 0 to use the caller's logon session.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The queries TGT.</returns>
        /// <remarks>Note that the session key will only be available if running with TCB privileges or the AllowTgtSessionKey option is enabled.</remarks>
        public static NtResult<KerberosExternalTicket> QueryTgt(Luid logon_id, bool throw_on_error)
        {
            var req_struct = new KERB_QUERY_TKT_CACHE_REQUEST() {
                MessageType = KERB_PROTOCOL_MESSAGE_TYPE.KerbRetrieveTicketMessage,
                LogonId = logon_id
            };
            using (var request = req_struct.ToBuffer())
            {
                using (var handle = SafeLsaLogonHandle.Connect(throw_on_error))
                {
                    if (!handle.IsSuccess)
                        return handle.Cast<KerberosExternalTicket>();
                    using (var result = CallPackage(handle.Result, request, throw_on_error))
                    {
                        if (!result.IsSuccess)
                            return result.Cast<KerberosExternalTicket>();
                        if (!result.Result.Status.IsSuccess())
                            return result.Result.Status.CreateResultFromError<KerberosExternalTicket>(throw_on_error);
                        KERB_EXTERNAL_TICKET ticket = result.Result.Buffer.Read<KERB_EXTERNAL_TICKET>(0);
                        if (!KerberosExternalTicket.TryParse(ticket, false, out KerberosExternalTicket ret))
                            return NtStatus.STATUS_INVALID_PARAMETER.CreateResultFromError<KerberosExternalTicket>(throw_on_error);
                        return ret.CreateResult();
                    }
                }
            }
        }

        /// <summary>
        /// Query for the TGT for a logon session.
        /// </summary>
        /// <param name="logon_id">The logon session ID. Specify 0 to use the caller's logon session.</param>
        /// <returns>The queries TGT.</returns>
        /// <remarks>Note that the session key will only be available if running with TCB privileges or the AllowTgtSessionKey option is enabled.</remarks>
        public static KerberosExternalTicket QueryTgt(Luid logon_id)
        {
            return QueryTgt(logon_id, true).Result;
        }

        /// <summary>
        /// Query for the TGT for the current logon session.
        /// </summary>
        /// <returns>The queries TGT.</returns>
        /// <remarks>Note that the session key will only be available if running with TCB privileges or the AllowTgtSessionKey option is enabled.</remarks>
        public static KerberosExternalTicket QueryTgt()
        {
            return QueryTgt(new Luid());
        }

        /// <summary>
        /// Purge the ticket cache.
        /// </summary>
        /// <param name="logon_id">The Logon Session ID to purge.</param>
        /// <param name="server_name">The name of the service tickets to delete.</param>
        /// <param name="realm_name">The realm of the tickets to delete.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public static NtStatus PurgeTicketCache(Luid logon_id, string server_name, string realm_name, bool throw_on_error)
        {
            using (var buffer = new SafeStructureInOutBuffer<KERB_PURGE_TKT_CACHE_REQUEST>(CalculateLength(server_name, realm_name), true))
            {
                using (var stm = buffer.Data.GetStream())
                {
                    BinaryWriter writer = new BinaryWriter(stm);
                    buffer.Result = new KERB_PURGE_TKT_CACHE_REQUEST()
                    {
                        MessageType = KERB_PROTOCOL_MESSAGE_TYPE.KerbPurgeTicketCacheMessage,
                        LogonId = logon_id,
                        ServerName = MarshalString(buffer.Data, writer, server_name),
                        RealmName = MarshalString(buffer.Data, writer, realm_name)
                    };
                }
                using (var handle = SafeLsaLogonHandle.Connect(throw_on_error))
                {
                    if (!handle.IsSuccess)
                        return handle.Status;
                    using (var result = CallPackage(handle.Result, buffer, throw_on_error))
                    {
                        return result.Result.Status.ToNtException(throw_on_error);
                    }
                }
            }
        }

        /// <summary>
        /// Purge the ticket cache.
        /// </summary>
        /// <param name="logon_id">The Logon Session ID to purge.</param>
        /// <param name="server_name">The name of the service tickets to delete.</param>
        /// <param name="realm_name">The realm of the tickets to delete.</param>
        public static void PurgeTicketCache(Luid logon_id, string server_name, string realm_name)
        {
            PurgeTicketCache(logon_id, server_name, realm_name, true);
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
            int length = 0;
            if (ticket_template != null)
            {
                length = CalculateLength(ticket_template.ClientName, ticket_template.ClientRealm,
                    ticket_template.ServerName, ticket_template.ServerRealm);
            }

            using (var buffer = new SafeStructureInOutBuffer<KERB_PURGE_TKT_CACHE_EX_REQUEST>(length, true))
            {
                using (var stm = buffer.Data.GetStream())
                {
                    KERB_TICKET_CACHE_INFO_EX ticket_info = new KERB_TICKET_CACHE_INFO_EX();
                    if (length > 0)
                    {
                        BinaryWriter writer = new BinaryWriter(stm);
                        ticket_info.ClientName = MarshalString(buffer.Data, writer, ticket_template.ClientName);
                        ticket_info.ClientRealm = MarshalString(buffer.Data, writer, ticket_template.ClientRealm);
                        ticket_info.ServerName = MarshalString(buffer.Data, writer, ticket_template.ServerName);
                        ticket_info.ServerRealm = MarshalString(buffer.Data, writer, ticket_template.ServerRealm);
                        ticket_info.EncryptionType = ticket_template.EncryptionType;
                        ticket_info.EndTime = ticket_template.EndTime.ToLargeIntegerStruct();
                        ticket_info.StartTime = ticket_template.StartTime.ToLargeIntegerStruct();
                        ticket_info.RenewTime = ticket_template.RenewTime.ToLargeIntegerStruct();
                        ticket_info.TicketFlags = ((uint)ticket_template.TicketFlags).RotateBits();
                    }

                    buffer.Result = new KERB_PURGE_TKT_CACHE_EX_REQUEST()
                    {
                        MessageType = KERB_PROTOCOL_MESSAGE_TYPE.KerbPurgeTicketCacheExMessage,
                        LogonId = logon_id,
                        Flags = purge_all_tickets ? KerberosPurgeTicketCacheExFlags.PurgeAllTickets : 0,
                        TicketTemplate = ticket_info
                    };
                }
                using (var handle = SafeLsaLogonHandle.Connect(throw_on_error))
                {
                    if (!handle.IsSuccess)
                        return handle.Status;
                    using (var result = CallPackage(handle.Result, buffer, throw_on_error))
                    {
                        return result.Result.Status.ToNtException(throw_on_error);
                    }
                }
            }
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

        /// <summary>
        /// Submit a ticket to the cache.
        /// </summary>
        /// <param name="ticket">The ticket to add in Kerberos Credential format.</param>
        /// <param name="logon_id">The Logon Session ID to submit the ticket to. 0 uses callers logon session.</param>
        /// <param name="key">Optional key to use if the credentials are encrypted.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public static NtStatus SubmitTicket(KerberosCredential ticket, Luid logon_id, KerberosAuthenticationKey key, bool throw_on_error)
        {
            if (ticket is null)
            {
                throw new ArgumentNullException(nameof(ticket));
            }

            byte[] ticket_data = ticket.ToArray();
            int additional_length = ticket_data.Length + (key?.Key.Length ?? 0);

            using (var buffer = new SafeStructureInOutBuffer<KERB_SUBMIT_TKT_REQUEST>(additional_length, true))
            {
                buffer.Data.WriteBytes(ticket_data);
                int base_offset = buffer.DataOffset;
                KERB_CRYPTO_KEY32 key_struct = new KERB_CRYPTO_KEY32();
                if (key != null)
                {
                    key_struct.KeyType = key.KeyEncryption;
                    key_struct.Length = key.Key.Length;
                    key_struct.Offset = base_offset + ticket_data.Length;
                    buffer.Data.WriteBytes((ulong)ticket_data.Length, key.Key);
                }

                buffer.Result = new KERB_SUBMIT_TKT_REQUEST()
                {
                    MessageType = KERB_PROTOCOL_MESSAGE_TYPE.KerbSubmitTicketMessage,
                    LogonId = logon_id,
                    KerbCredOffset = base_offset,
                    KerbCredSize = ticket_data.Length,
                    Key = key_struct
                };

                using (var handle = SafeLsaLogonHandle.Connect(throw_on_error))
                {
                    if (!handle.IsSuccess)
                        return handle.Status;
                    using (var result = CallPackage(handle.Result, buffer, throw_on_error))
                    {
                        if (!result.IsSuccess)
                            return result.Status;
                        return result.Result.Status.ToNtException(throw_on_error);
                    }
                }
            }
        }

        /// <summary>
        /// Submit a ticket to the cache.
        /// </summary>
        /// <param name="ticket">The ticket to add in Kerberos Credential format.</param>
        /// <param name="logon_id">The Logon Session ID to submit the ticket to. 0 uses callers logon session.</param>
        /// <param name="key">Optional key to use if the credentials are encrypted.</param>
        public static void SubmitTicket(KerberosCredential ticket, Luid logon_id = new Luid(), KerberosAuthenticationKey key = null)
        {
            SubmitTicket(ticket, logon_id, key, true);
        }
    }
}
