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

using NtCoreLib.Win32.Security.Interop;
using System;

namespace NtCoreLib.Win32.Security.Authentication.Kerberos;

/// <summary>
/// Flags for a ticket cache entry
/// </summary>
[Flags]
public enum KerberosTicketCacheInfoFlags
{
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
    None = 0,
    Primary = 1,
    Delegation = 2,
    S4U = 4,
    ASC = 8,
    EncInSKey = 0x10,
    X509 = 0x20,
    Fast = 0x40,
    Compound = 0x80,
    HubPrimary = 0x100,
    DisableTgtDelegation = 0x200
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
}

/// <summary>
/// Class to represent information about a ticket cache entry.
/// </summary>
public sealed class KerberosTicketCacheInfo
{
    /// <summary>
    /// The client name.
    /// </summary>
    public string ClientName { get; }
    /// <summary>
    /// The client realm.
    /// </summary>
    public string ClientRealm { get; }
    /// <summary>
    /// The server name.
    /// </summary>
    public string ServerName { get; }
    /// <summary>
    /// The server realm.
    /// </summary>
    public string ServerRealm { get;}
    /// <summary>
    /// The start time.
    /// </summary>
    public DateTime StartTime { get; }
    /// <summary>
    /// The end time.
    /// </summary>
    public DateTime EndTime { get; }
    /// <summary>
    /// The renew time.
    /// </summary>
    public DateTime RenewTime { get; }
    /// <summary>
    /// The key encryption type.
    /// </summary>
    public KerberosEncryptionType EncryptionType { get; }
    /// <summary>
    /// The ticket flags.
    /// </summary>
    public KerberosTicketFlags TicketFlags { get; }
    /// <summary>
    /// The session key type.
    /// </summary>
    public KerberosEncryptionType SessionKeyType { get; }
    /// <summary>
    /// The branch ID.
    /// </summary>
    public int BranchId { get; }
    /// <summary>
    /// The cache flags.
    /// </summary>
    public KerberosTicketCacheInfoFlags CacheFlags { get; }
    /// <summary>
    /// The KDC which was called.
    /// </summary>
    public string KdcCalled { get; }

    internal KerberosTicketCacheInfo(KERB_TICKET_CACHE_INFO_EX info)
    {
        ClientName = info.ClientName.ToString();
        ClientRealm = info.ClientRealm.ToString();
        ServerName = info.ServerName.ToString();
        ServerRealm = info.ServerRealm.ToString();
        StartTime = info.StartTime.ToDateTime();
        EndTime = info.EndTime.ToDateTime();
        RenewTime = info.RenewTime.ToDateTime();
        EncryptionType = info.EncryptionType;
        TicketFlags = (KerberosTicketFlags)info.TicketFlags.RotateBits();
    }

    internal KerberosTicketCacheInfo(KERB_TICKET_CACHE_INFO_EX2 info) : this(info.InfoEx)
    {
        SessionKeyType = info.SessionKeyType;
        BranchId = info.BranchId;
    }

    internal KerberosTicketCacheInfo(KERB_TICKET_CACHE_INFO_EX3 info) : this(info.InfoEx2)
    {
        CacheFlags = info.CacheFlags;
        KdcCalled = info.KdcCalled.ToString();
    }

    /// <summary>
    /// Constructor.
    /// </summary>
    /// <param name="client_name">The client name.</param>
    /// <param name="client_realm">The client realm.</param>
    /// <param name="server_name">The server name.</param>
    /// <param name="server_realm">The server realm.</param>
    /// <param name="start_time">The ticket start time.</param>
    /// <param name="end_time">The ticket end time.</param>
    /// <param name="renew_time">The ticket renew time.</param>
    /// <param name="encryption_type">The ticket encryption type.</param>
    /// <param name="ticket_flags">The ticket flags.</param>
    public KerberosTicketCacheInfo(string client_name, string client_realm, string server_name, string server_realm, 
        DateTime start_time, DateTime end_time, DateTime renew_time, KerberosEncryptionType encryption_type, KerberosTicketFlags ticket_flags)
    {
        if (string.IsNullOrEmpty(client_name))
        {
            throw new ArgumentException($"'{nameof(client_name)}' cannot be null or empty.", nameof(client_name));
        }

        if (string.IsNullOrEmpty(client_realm))
        {
            throw new ArgumentException($"'{nameof(client_realm)}' cannot be null or empty.", nameof(client_realm));
        }

        if (string.IsNullOrEmpty(server_name))
        {
            throw new ArgumentException($"'{nameof(server_name)}' cannot be null or empty.", nameof(server_name));
        }

        if (string.IsNullOrEmpty(server_realm))
        {
            throw new ArgumentException($"'{nameof(server_realm)}' cannot be null or empty.", nameof(server_realm));
        }

        ClientName = client_name;
        ClientRealm = client_realm;
        ServerName = server_name;
        ServerRealm = server_realm;
        StartTime = start_time;
        EndTime = end_time;
        RenewTime = renew_time;
        EncryptionType = encryption_type;
        TicketFlags = ticket_flags;
    }
}
