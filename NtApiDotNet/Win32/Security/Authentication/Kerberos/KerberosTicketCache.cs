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

using NtApiDotNet.Utilities.Reflection;
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

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct KERB_TICKET_CACHE_INFO_EX_IN
    {
        public UnicodeString ClientName;
        public UnicodeString ClientRealm;
        public UnicodeString ServerName;
        public UnicodeString ServerRealm;
        public LargeIntegerStruct StartTime;
        public LargeIntegerStruct EndTime;
        public LargeIntegerStruct RenewTime;
        public KerberosEncryptionType EncryptionType;
        public int TicketFlags;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct KERB_TICKET_CACHE_INFO_EX
    {
        public UnicodeStringOut ClientName;
        public UnicodeStringOut ClientRealm;
        public UnicodeStringOut ServerName;
        public UnicodeStringOut ServerRealm;
        public LargeIntegerStruct StartTime;
        public LargeIntegerStruct EndTime;
        public LargeIntegerStruct RenewTime;
        public KerberosEncryptionType EncryptionType;
        public int TicketFlags;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct KERB_TICKET_CACHE_INFO_EX2
    {
        public KERB_TICKET_CACHE_INFO_EX InfoEx;
        public KerberosEncryptionType SessionKeyType;
        public int BranchId;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct KERB_TICKET_CACHE_INFO_EX3
    {
        public KERB_TICKET_CACHE_INFO_EX2 InfoEx2;
        public KerberosTicketCacheInfoFlags CacheFlags;
        public UnicodeStringOut KdcCalled;
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

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct KERB_PURGE_TKT_CACHE_REQUEST
    {
        public KERB_PROTOCOL_MESSAGE_TYPE MessageType;
        public Luid LogonId;
        public UnicodeStringOut ServerName;
        public UnicodeStringOut RealmName;
    }

    [Flags]
    enum KerberosPurgeTicketCacheExFlags
    {
        None = 0,
        [SDKName("KERB_PURGE_ALL_TICKETS")]
        PurgeAllTickets = 1,
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct KERB_PURGE_TKT_CACHE_EX_REQUEST
    {
        public KERB_PROTOCOL_MESSAGE_TYPE MessageType;
        public Luid LogonId;
        public KerberosPurgeTicketCacheExFlags Flags;
        public KERB_TICKET_CACHE_INFO_EX_IN TicketTemplate;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct KERB_RETRIEVE_KEY_TAB_REQUEST
    {
        public KERB_PROTOCOL_MESSAGE_TYPE MessageType;
        public int Flags;
        public UnicodeStringOut UserName;
        public UnicodeStringOut DomainName;
        public UnicodeStringOut Password;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct KERB_RETRIEVE_KEY_TAB_RESPONSE
    {
        public KERB_PROTOCOL_MESSAGE_TYPE MessageType;
        public int KeyTabLength;
        public IntPtr KeyTab;
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

    [StructLayout(LayoutKind.Sequential)]
    internal struct KERB_CRYPTO_KEY32
    {
        public KerberosEncryptionType KeyType;
        public int Length;
        public int Offset;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct KERB_SUBMIT_TKT_REQUEST
    {
        public KERB_PROTOCOL_MESSAGE_TYPE MessageType;
        public Luid LogonId;
        public int Flags;
        public KERB_CRYPTO_KEY32 Key; // key to decrypt KERB_CRED
        public int KerbCredSize;
        public int KerbCredOffset;
    }

    /// <summary>
    /// Class to query the Kerberos Ticket Cache from LSASS.
    /// </summary>
    public static class KerberosTicketCache 
    {
        private static int CalculateLength(params string[] strs)
        {
            int ret = 0;
            foreach (var s in strs)
            {
                ret += CalculateLength(s?.Length);
            }
            return ret;
        }

        private static int CalculateLength(int? length)
        {
            int ret = length ?? 0;
            return (ret + 1) * 2;
        }

        private static UnicodeStringOut MarshalString(SafeBuffer buffer, BinaryWriter writer, byte[] value)
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

        private static UnicodeStringOut MarshalString(SafeBuffer buffer, BinaryWriter writer, string value)
        {
            return MarshalString(buffer, writer, value != null ? Encoding.Unicode.GetBytes(value) : null);
        }

        private static NtResult<LsaCallPackageResponse> CallPackage(SafeLsaLogonHandle handle, SafeBuffer buffer, bool throw_on_error)
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

        private static NtResult<SafeLsaReturnBufferHandle> QueryCachedTicketBuffer(SafeLsaLogonHandle handle, string target_name, KERB_RETRIEVE_TICKET_FLAGS flags,
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

        private static NtResult<KerberosExternalTicket> QueryCachedTicket(SafeLsaLogonHandle handle, string target_name, KERB_RETRIEVE_TICKET_FLAGS flags, 
            Luid logon_id, SecHandle sec_handle, bool throw_on_error)
        {
            using (var buffer = QueryCachedTicketBuffer(handle, target_name, flags, logon_id, sec_handle, throw_on_error))
            {
                if (!buffer.IsSuccess)
                    return buffer.Cast<KerberosExternalTicket>();

                KERB_EXTERNAL_TICKET ticket = buffer.Result.Read<KERB_EXTERNAL_TICKET>(0);
                if (!KerberosExternalTicket.TryParse(ticket, flags.HasFlagSet(KERB_RETRIEVE_TICKET_FLAGS.AsKerbCred), out KerberosExternalTicket ret))
                    return NtStatus.STATUS_INVALID_PARAMETER.CreateResultFromError<KerberosExternalTicket>(throw_on_error);
                return ret.CreateResult();
            }
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
            using (var handle = SafeLsaLogonHandle.Connect(throw_on_error))
            {
                if (!handle.IsSuccess)
                    return handle.Cast<KerberosExternalTicket>();
                Luid luid = logon_id;
                KERB_RETRIEVE_TICKET_FLAGS flags = cached_only ? KERB_RETRIEVE_TICKET_FLAGS.UseCacheOnly : KERB_RETRIEVE_TICKET_FLAGS.Default;
                return QueryCachedTicket(handle.Result, target_name, flags | KERB_RETRIEVE_TICKET_FLAGS.AsKerbCred,
                    luid, new SecHandle(), throw_on_error);
            }
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
            using (var handle = SafeLsaLogonHandle.Connect(throw_on_error))
            {
                if (!handle.IsSuccess)
                    return handle.Cast<KerberosExternalTicket>();
                KERB_RETRIEVE_TICKET_FLAGS flags = cached_only ? KERB_RETRIEVE_TICKET_FLAGS.UseCacheOnly : KERB_RETRIEVE_TICKET_FLAGS.Default;
                flags |= KERB_RETRIEVE_TICKET_FLAGS.UseCredHandle | KERB_RETRIEVE_TICKET_FLAGS.AsKerbCred;
                return QueryCachedTicket(handle.Result, target_name, flags,
                    default, credential_handle.CredHandle, throw_on_error);
            }
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
                        KERB_RETRIEVE_TICKET_FLAGS.UseCacheOnly | KERB_RETRIEVE_TICKET_FLAGS.AsKerbCred, 
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
        /// Get a key tab for a user.
        /// </summary>
        /// <param name="credentials">The user's credentials.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The kerberos keytab.</returns>
        [SupportedVersion(SupportedVersion.Windows10)]
        public static NtResult<KerberosKeySet> GetKeyTab(UserCredentials credentials, bool throw_on_error)
        {
            if (credentials is null)
            {
                throw new ArgumentNullException(nameof(credentials));
            }

            using (var list = new DisposableList())
            {
                int total_str_size = CalculateLength(credentials.UserName, credentials.Domain) + CalculateLength(credentials.Password?.Length);
                var buffer = new SafeStructureInOutBuffer<KERB_RETRIEVE_KEY_TAB_REQUEST>(total_str_size, true);

                using (var strs = buffer.Data.GetStream())
                {
                    BinaryWriter writer = new BinaryWriter(strs);
                    UnicodeStringOut username = MarshalString(buffer.Data, writer, credentials.UserName);
                    UnicodeStringOut domain = MarshalString(buffer.Data, writer, credentials.Domain);
                    UnicodeStringOut password = MarshalString(buffer.Data, writer, credentials.GetPasswordBytes());

                    buffer.Result = new KERB_RETRIEVE_KEY_TAB_REQUEST()
                    {
                        MessageType = KERB_PROTOCOL_MESSAGE_TYPE.KerbRetrieveKeyTabMessage,
                        UserName = username,
                        DomainName = domain,
                        Password = password
                    };
                }

                using (var handle = SafeLsaLogonHandle.Connect(throw_on_error))
                {
                    if (!handle.IsSuccess)
                        return handle.Cast<KerberosKeySet>();
                    using (var result = CallPackage(handle.Result, buffer, throw_on_error))
                    {
                        if (!result.IsSuccess)
                            return result.Status.CreateResultFromError<KerberosKeySet>(throw_on_error);
                        if (!result.Result.Status.IsSuccess())
                            return result.Result.Status.CreateResultFromError<KerberosKeySet>(throw_on_error);

                        var keytab = result.Result.Buffer.Read<KERB_RETRIEVE_KEY_TAB_RESPONSE>(0);
                        var keytab_buffer = new SafeHGlobalBuffer(keytab.KeyTab, keytab.KeyTabLength, false);

                        return KerberosKeySet.ReadKeyTabFile(keytab_buffer.GetStream()).CreateResult();
                    }
                }
            }
        }

        /// <summary>
        /// Get a key tab for a user.
        /// </summary>
        /// <param name="credentials">The user's credentials.</param>
        /// <returns>The kerberos keytab.</returns>
        [SupportedVersion(SupportedVersion.Windows10)]
        public static KerberosKeySet GetKeyTab(UserCredentials credentials)
        {
            return GetKeyTab(credentials, true).Result;
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
