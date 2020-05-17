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
using System.Linq;
using System.Runtime.InteropServices;

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos
{
    internal enum KERB_PROTOCOL_MESSAGE_TYPE
    {
        KerbDebugRequestMessage,
        KerbQueryTicketCacheMessage,
        KerbChangeMachinePasswordMessage,
        KerbVerifyPacMessage,
        KerbRetrieveTicketMessage,
        KerbUpdateAddressesMessage,
        KerbPurgeTicketCacheMessage,
        KerbChangePasswordMessage,
        KerbRetrieveEncodedTicketMessage,
        KerbDecryptDataMessage,
        KerbAddBindingCacheEntryMessage,
        KerbSetPasswordMessage,
        KerbSetPasswordExMessage,
        KerbVerifyCredentialsMessage,
        KerbQueryTicketCacheExMessage,
        KerbPurgeTicketCacheExMessage,
        KerbRefreshSmartcardCredentialsMessage,
        KerbAddExtraCredentialsMessage2,
        KerbQuerySupplementalCredentialsMessage,
        KerbTransferCredentialsMessage,
        KerbQueryTicketCacheEx2Message,
        KerbSubmitTicketMessage,
        KerbAddExtraCredentialsExMessage,
        KerbQueryKdcProxyCacheMessage,
        KerbPurgeKdcProxyCacheMessage,
        KerbQueryTicketCacheEx3Message,
        KerbCleanupMachinePkinitCredsMessage,
        KerbAddBindingCacheEntryExMessage,
        KerbQueryBindingCacheMessage,
        KerbPurgeBindingCacheMessage,
        KerbPinKdcMessage,
        KerbUnpinAllKdcsMessage,
        KerbQueryDomainExtendedPoliciesMessage,
        KerbQueryS4U2ProxyCacheMessage,
        KerbRetrieveKeyTabMessage
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct KERB_QUERY_TKT_CACHE_REQUEST
    {
        public KERB_PROTOCOL_MESSAGE_TYPE MessageType;
        public Luid LogonId;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct KERB_TICKET_CACHE_INFO
    {
        public UnicodeStringOut ServerName;
        public UnicodeStringOut RealmName;
        public LargeIntegerStruct StartTime;
        public LargeIntegerStruct EndTime;
        public LargeIntegerStruct RenewTime;
        public KerberosEncryptionType EncryptionType;
        public int TicketFlags;
    }

    [StructLayout(LayoutKind.Sequential), DataStart("Tickets")]
    internal struct KERB_QUERY_TKT_CACHE_RESPONSE
    {
        public KERB_PROTOCOL_MESSAGE_TYPE MessageType;
        public int CountOfTickets;
        public KERB_TICKET_CACHE_INFO Tickets;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct KERB_QUERY_TKT_CACHE_RESPONSE_HEADER
    {
        public KERB_PROTOCOL_MESSAGE_TYPE MessageType;
        public int CountOfTickets;
    }

    [Flags]
    internal enum KERB_RETRIEVE_TICKET_FLAGS
    {
        Default = 0,
        DontUseCache = 1,
        UseCacheOnly = 2,
        UseCredHandle = 4,
        AsKerbCred = 8,
        WithSecCred = 0x10,
        CacheTicket = 0x20,
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct KERB_RETRIEVE_TKT_REQUEST
    {
        public KERB_PROTOCOL_MESSAGE_TYPE MessageType;
        public Luid LogonId;
        public UnicodeStringOut TargetName;
        public int TicketFlags;
        public KERB_RETRIEVE_TICKET_FLAGS CacheOptions;
        public KerberosEncryptionType EncryptionType;
        public SecHandle CredentialsHandle;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct KERB_RETRIEVE_TKT_RESPONSE
    {
        public KERB_EXTERNAL_TICKET Ticket;
    }

    [StructLayout(LayoutKind.Sequential), DataStart("Names")]
    internal struct KERB_EXTERNAL_NAME
    {
        public short NameType;
        public short NameCount;
        public UnicodeStringOut Names;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct KERB_CRYPTO_KEY
    {
        public KerberosEncryptionType KeyType;
        public int Length;
        public IntPtr Value;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct KERB_EXTERNAL_TICKET
    {
        public IntPtr ServiceName; // PKERB_EXTERNAL_NAME
        public IntPtr TargetName;  // PKERB_EXTERNAL_NAME
        public IntPtr ClientName;  // PKERB_EXTERNAL_NAME
        public UnicodeStringOut DomainName;
        public UnicodeStringOut TargetDomainName;
        public UnicodeStringOut AltTargetDomainName;
        public KERB_CRYPTO_KEY SessionKey;
        public int TicketFlags;
        public int Flags;
        public LargeIntegerStruct KeyExpirationTime;
        public LargeIntegerStruct StartTime;
        public LargeIntegerStruct EndTime;
        public LargeIntegerStruct RenewUntil;
        public LargeIntegerStruct TimeSkew;
        public int EncodedTicketSize;
        public IntPtr EncodedTicket;

        internal byte[] ReadTicket()
        {
            byte[] ret = new byte[EncodedTicketSize];
            Marshal.Copy(EncodedTicket, ret, 0, ret.Length);
            return ret;
        }
    }

    internal struct KerberosTicketCacheInfo
    {
        public string ServerName;
        public string RealmName;
        public DateTime StartTime;
        public DateTime EndTime;
        public DateTime RenewTime;
        public KerberosEncryptionType EncryptionType;
        public KerberosTicketFlags TicketFlags;

        internal KerberosTicketCacheInfo(KERB_TICKET_CACHE_INFO info)
        {
            ServerName = info.ServerName.ToString();
            RealmName = info.RealmName.ToString();
            StartTime = info.StartTime.ToDateTime();
            EndTime = info.EndTime.ToDateTime();
            RenewTime = info.RenewTime.ToDateTime();
            EncryptionType = info.EncryptionType;
            TicketFlags = (KerberosTicketFlags) info.TicketFlags.SwapEndian();
        }
    }

    /// <summary>
    /// Class to query the Kerberos Ticket Cache from LSASS.
    /// </summary>
    public static class KerberosTicketCache 
    {
        private static NtResult<KerberosTicketCacheInfo[]> QueryTicketCacheList(SafeLsaLogonHandle handle, Luid logon_id, bool throw_on_error)
        {
            var package = handle.LookupAuthPackage(AuthenticationPackage.KERBEROS_NAME, throw_on_error);
            if (!package.IsSuccess)
                return package.Cast<KerberosTicketCacheInfo[]>();
            var request_struct = new KERB_QUERY_TKT_CACHE_REQUEST()
            {
                LogonId = logon_id,
                MessageType = KERB_PROTOCOL_MESSAGE_TYPE.KerbQueryTicketCacheMessage
            };
            using (var request = request_struct.ToBuffer())
            {
                using (var result = handle.CallPackage(package.Result, request, throw_on_error))
                {
                    if (!result.IsSuccess)
                        return result.Cast<KerberosTicketCacheInfo[]>();
                    if (!result.Result.Status.IsSuccess())
                        return result.Result.Status.CreateResultFromError<KerberosTicketCacheInfo[]>(throw_on_error);
                    var response = result.Result.Buffer.Read<KERB_QUERY_TKT_CACHE_RESPONSE_HEADER>(0);
                    if (response.CountOfTickets == 0)
                        return new KerberosTicketCacheInfo[0].CreateResult();
                    var buffer = BufferUtils.GetStructAtOffset<KERB_QUERY_TKT_CACHE_RESPONSE>(result.Result.Buffer, 0);
                    KERB_TICKET_CACHE_INFO[] infos = new KERB_TICKET_CACHE_INFO[response.CountOfTickets];
                    buffer.Data.ReadArray(0, infos, 0, response.CountOfTickets);
                    return infos.Select(i => new KerberosTicketCacheInfo(i)).ToArray().CreateResult();
                }
            }
        }

        internal static NtResult<KerberosTicketCacheInfo[]> QueryTicketCacheList(Luid logon_id, bool throw_on_error)
        {
            using (var handle = SafeLsaLogonHandle.Connect(throw_on_error))
            {
                if (!handle.IsSuccess)
                    return handle.Cast<KerberosTicketCacheInfo[]>();
                return QueryTicketCacheList(handle.Result, logon_id, throw_on_error);
            }
        }

        private static NtResult<SafeLsaReturnBufferHandle> QueryCachedTicket(SafeLsaLogonHandle handle, uint auth_package, string target_name, KERB_RETRIEVE_TICKET_FLAGS flags,
            Luid logon_id, SecHandle sec_handle, bool throw_on_error)
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
                    TargetName = new UnicodeStringOut()
                    {
                        Length = (ushort)string_length,
                        MaximumLength = (ushort)max_string_length,
                        Buffer = request.Data.DangerousGetHandle()
                    }
                };
                request.Result = request_str;
                using (var result = handle.CallPackage(auth_package, request, throw_on_error))
                {
                    if (!result.IsSuccess)
                        return result.Cast<SafeLsaReturnBufferHandle>();
                    if (!result.Result.Status.IsSuccess())
                        return result.Result.Status.CreateResultFromError<SafeLsaReturnBufferHandle>(throw_on_error);
                    return result.Result.Buffer.Detach().CreateResult();
                }
            }
        }

        private static NtResult<KerberosExternalTicket> QueryCachedTicket(SafeLsaLogonHandle handle, string target_name, KERB_RETRIEVE_TICKET_FLAGS flags, 
            Luid logon_id, SecHandle sec_handle, bool throw_on_error)
        {
            var package = handle.LookupAuthPackage(AuthenticationPackage.KERBEROS_NAME, throw_on_error);
            if (!package.IsSuccess)
                return package.Cast<KerberosExternalTicket>();

            using (var buffer = QueryCachedTicket(handle, package.Result, target_name, flags, logon_id, sec_handle, throw_on_error))
            {
                if (!buffer.IsSuccess)
                    return buffer.Cast<KerberosExternalTicket>();

                KERB_EXTERNAL_TICKET ticket = buffer.Result.Read<KERB_EXTERNAL_TICKET>(0);
                if (!KerberosExternalTicket.TryParse(ticket, out KerberosExternalTicket ret))
                    return NtStatus.STATUS_INVALID_PARAMETER.CreateResultFromError<KerberosExternalTicket>(throw_on_error);
                return ret.CreateResult();
            }
        }

        /// <summary>
        /// Get a Kerberos Ticket.
        /// </summary>
        /// <param name="target_name">The target service for the Ticket.</param>
        /// <param name="cached_only">True to only query for cached tickets.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The Kerberos Ticket.</returns>
        public static NtResult<KerberosExternalTicket> GetTicket(string target_name, bool cached_only, bool throw_on_error)
        {
            using (var handle = SafeLsaLogonHandle.Connect(throw_on_error))
            {
                if (!handle.IsSuccess)
                    return handle.Cast<KerberosExternalTicket>();
                Luid luid = NtToken.PseudoEffectiveToken.AuthenticationId;
                KERB_RETRIEVE_TICKET_FLAGS flags = cached_only ? KERB_RETRIEVE_TICKET_FLAGS.UseCacheOnly : KERB_RETRIEVE_TICKET_FLAGS.Default;
                return QueryCachedTicket(handle.Result, target_name, flags,
                    luid, new SecHandle(), throw_on_error);
            }
        }

        /// <summary>
        /// Get a Kerberos Ticket.
        /// </summary>
        /// <param name="target_name">The target service for the Ticket.</param>
        /// <param name="cached_only">True to only query for cached tickets.</param>
        /// <returns>The Kerberos Ticket.</returns>
        public static KerberosExternalTicket GetTicket(string target_name, bool cached_only)
        {
            return GetTicket(target_name, cached_only, true).Result;
        }

        /// <summary>
        /// Get a Kerberos Ticket.
        /// </summary>
        /// <param name="target_name">The target service for the Ticket.</param>
        /// <returns>The Kerberos Ticket.</returns>
        public static KerberosExternalTicket GetTicket(string target_name)
        {
            return GetTicket(target_name, false);
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
                    var ticket = QueryCachedTicket(handle.Result, $"{info.ServerName}@{info.RealmName}", KERB_RETRIEVE_TICKET_FLAGS.UseCacheOnly, 
                        logon_id, new SecHandle(), false);
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
    }
}
