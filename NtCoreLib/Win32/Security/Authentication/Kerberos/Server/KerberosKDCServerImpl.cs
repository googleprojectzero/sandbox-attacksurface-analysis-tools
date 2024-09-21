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

using NtCoreLib.Security.Authorization;
using NtCoreLib.Utilities.ASN1.Builder;
using NtCoreLib.Win32.Security.Authentication.Kerberos.Builder;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;

namespace NtCoreLib.Win32.Security.Authentication.Kerberos.Server;

internal sealed class KerberosKDCServerImpl : KerberosKDCServerToken
{
    private readonly KerberosKDCServerConfig _config;
    private readonly string _realm;
    private readonly string _domain;
    private readonly Sid _domain_sid;
    private readonly Dictionary<KerberosPrincipalName, KerberosKDCServerUser> _users;
    private readonly KerberosKeySet _derived_keys;
    private readonly KerberosKeySet _keys;
    private readonly KerberosAuthenticationKey _krbtgt_key;
    private readonly KerberosPrincipalName _krbtgt_name;

    public KerberosKDCServerImpl(KerberosKDCServerConfig config) 
        : base(config.Listener ?? new KerberosKDCServerListenerTCP(IPAddress.Loopback, 88))
    {
        _config = config;
        _realm = config.Realm?.ToUpper() ?? string.Empty;
        if (string.IsNullOrWhiteSpace(_realm))
            throw new ArgumentException("Must specify a realm.");
        _domain = _realm.Split('.')[0];
        _krbtgt_name = new KerberosPrincipalName(KerberosNameType.SRV_INST, $"krbtgt/{_realm}");
        _krbtgt_key = (_config.KrbTgtKey ?? KerberosAuthenticationKey.GenerateKey(KerberosEncryptionType.AES256_CTS_HMAC_SHA1_96)).CloneWithName(_krbtgt_name, _realm);
        _domain_sid = config.DomainSid ?? Sid.Parse("S-1-5-21").CreateRandom(3);
        _users = config.Users.ToDictionary(u => new KerberosPrincipalName(KerberosNameType.PRINCIPAL, u.UserName));
        _keys = new KerberosKeySet();
        _keys.Add(_krbtgt_key.CloneWithName(new KerberosPrincipalName(KerberosNameType.SRV_INST, "krbtgt"), _realm));
        _keys.Add(_krbtgt_key.CloneWithName(_krbtgt_name, _realm));
        foreach (var user in _users.Values.Where(u => u.ServicePrincipalNames.Count > 0))
        {
            foreach (var key in user.Keys)
            {
                _keys.Add(key.CloneWithName(new KerberosPrincipalName(KerberosNameType.PRINCIPAL, user.UserName), _realm));
                foreach (var spn in user.ServicePrincipalNames)
                {
                    _keys.Add(key.CloneWithName(spn, _realm));
                }
            }
        }
        foreach (var key in config.AdditionalKeys)
        {
            _keys.Add(key);
        }
        _derived_keys = new KerberosKeySet();
    }

    private AuthenticationToken GetGenericError()
    {
        return GetError(KerberosErrorType.GENERIC, null);
    }

    private AuthenticationToken GetError(KerberosErrorType error, KerberosKDCRequestAuthenticationToken request, byte[] error_data = null)
    {
        return KerberosErrorAuthenticationToken.Create(KerberosTime.Now, 0, error, _realm,
            request?.ServerName ?? new KerberosPrincipalName(KerberosNameType.SRV_INST, "UNKNOWN"), 
            error_data: error_data, no_gssapi_wrapper: true);
    }

    private static byte[] CreateU2UErrorData()
    {
        KerberosTypedData error = new(KerberosTypedDataType.MustUseUser2User, Array.Empty<byte>());
        DERBuilder builder = new();
        builder.WriteSequence(new[] { error });
        return builder.ToArray();
    }

    private KerberosExternalTicket CreateTicket(KerberosAuthenticationKey key,
        KerberosPrincipalName server_name, KerberosPrincipalName client_name,
        string realm, KerberosTime auth_time, KerberosAuthorizationDataPACBuilder pac,
        IEnumerable<KerberosEncryptionType> enc_types, KerberosTicketFlags flags)
    {
        if (key is null)
        {
            throw new ArgumentNullException(nameof(key));
        }

        if (server_name is null)
        {
            throw new ArgumentNullException(nameof(server_name));
        }

        if (client_name is null)
        {
            throw new ArgumentNullException(nameof(client_name));
        }

        if (string.IsNullOrEmpty(realm))
        {
            throw new ArgumentException($"'{nameof(realm)}' cannot be null or empty.", nameof(realm));
        }

        pac.ComputeSignatures(key, _krbtgt_key);

        KerberosAuthenticationKey ticket_key = 
            KerberosAuthenticationKey.GenerateKey(enc_types?.FirstOrDefault() ?? KerberosEncryptionType.AES256_CTS_HMAC_SHA1_96);

        KerberosAuthorizationDataIfRelevantBuilder if_rel = new();
        if_rel.Entries.Add(pac);

        List<KerberosAuthorizationData> auth_data = new();
        auth_data.Add(if_rel.Create());

        if (_users.TryGetValue(client_name, out KerberosKDCServerUser user))
        {
            auth_data.AddRange(user.AuthorizationData);
        }

        KerberosTicketBuilder ticket_builder = new(5, realm, server_name, flags, realm, client_name,
            auth_time, KerberosTime.Now, KerberosTime.MaximumTime, KerberosTime.MaximumTime, ticket_key,
            new KerberosTransitedEncoding(KerberosTransitedEncodingType.X500Compress, Array.Empty<byte>()), null, auth_data);

        var ticket_dec = ticket_builder.Create();
        var ticket = ticket_dec.Encrypt(key);
        return KerberosCredential.Create(ticket, ticket_dec.ToCredentialInfo()).ToExternalTicket();
    }

    private KerberosTicketFlags OptionsToFlags(KerberosKDCOptions options)
    {
        var ret = KerberosTicketFlags.None;
        if (options.HasFlagSet(KerberosKDCOptions.Forwardable))
            ret |= KerberosTicketFlags.Forwardable;
        if (options.HasFlagSet(KerberosKDCOptions.Renewable))
            ret |= KerberosTicketFlags.Renewable;
        return ret;
    }

    private AuthenticationToken HandleAsRequest(KerberosKDCRequestAuthenticationToken request)
    {
        string request_realm = request.Realm?.ToUpper();
        if (request_realm != _realm && request_realm != _domain)
            return GetError(KerberosErrorType.WRONG_REALM, request);
        if (!_users.TryGetValue(request.ClientName, out KerberosKDCServerUser user))
            return GetError(KerberosErrorType.S_PRINCIPAL_UNKNOWN, request);
        if (request.EncryptionTypes.Count == 0)
            return GetError(KerberosErrorType.ENCTYPE_NOSUPP, request);
        var key = user.Keys.FindKey(request.EncryptionTypes);
        if (key == null && user.Password != null)
        {
            key = _derived_keys.FindKeySetForPrincipal(request.ClientName)?.FindKey(request.EncryptionTypes);
            if (key == null)
            {
                key = KerberosAuthenticationKey.DeriveKey(request.EncryptionTypes.First(), user.Password, 4096, request.ClientName, _realm, 0);
                _derived_keys.Add(key);
            }
        }
        if (key == null)
            return GetError(KerberosErrorType.NOKEY, request);

        KerberosTime auth_time = KerberosTime.Now;
        var pac = user.CreatePac(KerberosTime.Now, _domain_sid, _realm);
        var ticket = CreateTicket(_krbtgt_key, _krbtgt_name, request.ClientName, 
            _realm, auth_time, pac, request.EncryptionTypes, KerberosTicketFlags.Initial | OptionsToFlags(request.KDCOptions));
        KerberosASReplyEncryptedPartBuilder reply_enc = new();
        reply_enc.InitializeFromTicket(ticket, request);

        KerberosASReplyBuilder reply = new()
        {
            ClientName = request.ClientName,
            ClientRealm = _realm,
            Ticket = ticket.Ticket,
            EncryptedData = reply_enc.Create().Encrypt(key, 
                key.KeyEncryption == KerberosEncryptionType.ARCFOUR_HMAC_MD5 ? KerberosKeyUsage.TgsRepEncryptedPart : KerberosKeyUsage.AsRepEncryptedPart)
        };

        string salt = null;
        switch (key.KeyEncryption)
        {
            case KerberosEncryptionType.AES128_CTS_HMAC_SHA1_96:
            case KerberosEncryptionType.AES256_CTS_HMAC_SHA1_96:
                salt = _realm + string.Join("", request.ClientName.Names);
                break;
        }

        reply.AddPreAuthenticationData(new KerberosPreAuthenticationDataEncryptionTypeInfo2(key.KeyEncryption, salt));

        return reply.Create();
    }

    private KerberosErrorType DecryptKrbTgtTicket(KerberosTicket ticket, out KerberosTicketDecrypted ticket_dec)
    {
        ticket_dec = null;

        if (ticket.ServerName != _krbtgt_name)
            return KerberosErrorType.S_PRINCIPAL_UNKNOWN;

        if (ticket.Realm != _realm)
            return KerberosErrorType.WRONG_REALM;

        if (!ticket.TryDecrypt(new KerberosKeySet(_krbtgt_key), KerberosKeyUsage.AsRepTgsRepTicket, out ticket_dec))
            return KerberosErrorType.MODIFIED;

        return KerberosErrorType.NONE;
    }

    private KerberosErrorType GetTicketServiceKey(KerberosKDCRequestAuthenticationToken request, out KerberosAuthenticationKey service_key)
    {
        service_key = null;

        if (request.KDCOptions.HasFlagSet(KerberosKDCOptions.EncTicketInSessionKey))
        {
            if (request.AdditionalTickets.Count == 0)
                return KerberosErrorType.BADOPTION;
            var error = DecryptKrbTgtTicket(request.AdditionalTickets[0], out KerberosTicketDecrypted ticket_dec);
            if (error != KerberosErrorType.NONE)
                return error;
            service_key = ticket_dec.Key;
        }
        else
        {
            service_key = _keys.FindKeySetForPrincipal(request.ServerName).FindKey(request.EncryptionTypes);
        }

        return service_key == null ? KerberosErrorType.S_PRINCIPAL_UNKNOWN : KerberosErrorType.NONE;
    }

    private AuthenticationToken HandleTgsRequest(KerberosKDCRequestAuthenticationToken request)
    {
        string request_realm = request.Realm?.ToUpper();
        if (request_realm != _realm && request_realm != _domain)
            return GetError(KerberosErrorType.WRONG_REALM, request);

        if (request.KDCOptions.HasFlagSet(KerberosKDCOptions.Renew))
            return GetError(KerberosErrorType.BADOPTION, request);

        var error = GetTicketServiceKey(request, out KerberosAuthenticationKey service_key);
        if (error != KerberosErrorType.NONE)
        {
            byte[] error_data = null;
            if (error == KerberosErrorType.S_PRINCIPAL_UNKNOWN && _users.ContainsKey(request.ServerName))
            {
                error_data = CreateU2UErrorData();
            }

            return GetError(error, request, error_data);
        }

        var tgs_req = request.PreAuthenticationData.OfType<KerberosPreAuthenticationDataTGSRequest>().FirstOrDefault();
        if (tgs_req == null)
            return GetError(KerberosErrorType.BADOPTION, request);

        error = DecryptKrbTgtTicket(tgs_req.Ticket, out KerberosTicketDecrypted ticket_dec);
        if (error != KerberosErrorType.NONE)
            return GetError(error, request);

        if (!tgs_req.Authenticator.TryDecrypt(ticket_dec.Key, KerberosKeyUsage.TgsReqPaTgsReqApReq, out KerberosEncryptedData auth_dec))
            return GetError(KerberosErrorType.MODIFIED, request);

        if (!KerberosAuthenticator.TryParse(auth_dec.CipherText, out KerberosAuthenticator auth))
            return GetError(KerberosErrorType.BADOPTION, request);

        var pac = (KerberosAuthorizationDataPACBuilder)ticket_dec.FindPAC()?.ToBuilder();
        if (pac == null)
            return GetError(KerberosErrorType.C_PRINCIPAL_UNKNOWN, request);

        pac.ComputeSignatures(service_key, _krbtgt_key);

        var ticket = CreateTicket(service_key, request.ServerName, ticket_dec.ClientName,
            _realm, ticket_dec.AuthTime, pac, request.EncryptionTypes, OptionsToFlags(request.KDCOptions));
        KerberosTGSReplyEncryptedPartBuilder reply_enc = new();
        reply_enc.InitializeFromTicket(ticket, request);

        KerberosKeyUsage key_usage = auth.SubKey != null ? KerberosKeyUsage.TgsRepEncryptedPartAuthSubkey : KerberosKeyUsage.TgsRepEncryptedPart;
        var session_key = auth.SubKey ?? ticket_dec.Key;

        var reply = new KerberosTGSReplyBuilder
        {
            ClientName = ticket_dec.ClientName,
            ClientRealm = ticket_dec.ClientRealm,
            Ticket = ticket.Ticket,
            EncryptedData = reply_enc.Create().Encrypt(session_key, key_usage)
        };

        return reply.Create();
    }

    protected override AuthenticationToken HandleRequest(KerberosKDCRequestAuthenticationToken request)
    {
        try
        {
            if (request.MessageType == KerberosMessageType.KRB_AS_REQ)
                return HandleAsRequest(request);
            if (request.MessageType == KerberosMessageType.KRB_TGS_REQ)
                return HandleTgsRequest(request);
        }
        catch
        {
        }

        return GetGenericError();
    }
}
