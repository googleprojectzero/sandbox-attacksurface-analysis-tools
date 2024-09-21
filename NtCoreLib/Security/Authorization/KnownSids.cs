//  Copyright 2019 Google Inc. All Rights Reserved.
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
using System.Collections.Generic;

namespace NtCoreLib.Security.Authorization;

/// <summary>
/// Static methods to get some known SIDs.
/// </summary>
public static class KnownSids
{
    /// <summary>
    /// NULL SID
    /// </summary>
    public static Sid Null => GetKnownSid(KnownSidValue.Null);

    /// <summary>
    /// Everyone SID
    /// </summary>
    public static Sid World => GetKnownSid(KnownSidValue.World);

    /// <summary>
    /// Local user SID
    /// </summary>
    public static Sid Local => GetKnownSid(KnownSidValue.Local);

    /// <summary>
    /// CREATOR OWNER SID
    /// </summary>
    public static Sid CreatorOwner => GetKnownSid(KnownSidValue.CreatorOwner);

    /// <summary>
    /// CREATOR GROUP SID
    /// </summary>
    public static Sid CreatorGroup => GetKnownSid(KnownSidValue.CreatorGroup);

    /// <summary>
    /// CREATOR OWNER SERVER SID
    /// </summary>
    public static Sid CreatorOwnerServer => GetKnownSid(KnownSidValue.CreatorOwnerServer);

    /// <summary>
    /// CREATOR OWNER SERVER SID
    /// </summary>
    public static Sid CreatorGroupServer => GetKnownSid(KnownSidValue.CreatorGroupServer);

    /// <summary>
    /// Service SID
    /// </summary>
    public static Sid Service => GetKnownSid(KnownSidValue.Service);

    /// <summary>
    /// ANONYMOUS LOGON SID
    /// </summary>
    public static Sid Anonymous => GetKnownSid(KnownSidValue.Anonymous);

    /// <summary>
    /// Authenticated Users SID
    /// </summary>
    public static Sid AuthenticatedUsers => GetKnownSid(KnownSidValue.AuthenticatedUsers);

    /// <summary>
    /// RESTRICTED SID
    /// </summary>
    public static Sid Restricted => GetKnownSid(KnownSidValue.Restricted);

    /// <summary>
    /// NT AUTHORITY\WRITE RESTRICTED
    /// </summary>
    public static Sid WriteRestricted => GetKnownSid(KnownSidValue.WriteRestricted);

    /// <summary>
    /// BUILTIN\BUILTIN
    /// </summary>
    public static Sid Builtin => GetKnownSid(KnownSidValue.Builtin);

    /// <summary>
    /// NT AUTHORITY\INTERACTIVE
    /// </summary>
    public static Sid Interactive => GetKnownSid(KnownSidValue.Interactive);

    /// <summary>
    /// NT AUTHORITY\DIALUP
    /// </summary>
    public static Sid Dialup => GetKnownSid(KnownSidValue.Dialup);

    /// <summary>
    /// NT AUTHORITY\NETWORK
    /// </summary>
    public static Sid Network => GetKnownSid(KnownSidValue.Network);

    /// <summary>
    /// NT AUTHORITY\BATCH
    /// </summary>
    public static Sid Batch => GetKnownSid(KnownSidValue.Batch);

    /// <summary>
    /// NT AUTHORITY\PROXY
    /// </summary>
    public static Sid Proxy => GetKnownSid(KnownSidValue.Proxy);

    /// <summary>
    /// LOCAL SYSTEM SID
    /// </summary>
    public static Sid LocalSystem => GetKnownSid(KnownSidValue.LocalSystem);

    /// <summary>
    /// LOCAL SERVICE SID
    /// </summary>
    public static Sid LocalService => GetKnownSid(KnownSidValue.LocalService);

    /// <summary>
    /// NETWORK SERVICE SID
    /// </summary>
    public static Sid NetworkService => GetKnownSid(KnownSidValue.NetworkService);

    /// <summary>
    /// APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES SID
    /// </summary>
    public static Sid AllApplicationPackages => GetKnownSid(KnownSidValue.AllApplicationPackages);

    /// <summary>
    /// APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES
    /// </summary>
    public static Sid AllRestrictedApplicationPackages => GetKnownSid(KnownSidValue.AllRestrictedApplicationPackages);

    /// <summary>
    /// NT SERVICE\TrustedInstaller
    /// </summary>
    public static Sid TrustedInstaller => GetKnownSid(KnownSidValue.TrustedInstaller);

    /// <summary>
    /// BUILTIN\Users
    /// </summary>
    public static Sid BuiltinUsers => GetKnownSid(KnownSidValue.BuiltinUsers);

    /// <summary>
    /// BUILTIN\Administrators
    /// </summary>
    public static Sid BuiltinAdministrators => GetKnownSid(KnownSidValue.BuiltinAdministrators);

    /// <summary>
    /// APPLICATION PACKAGE AUTHORITY\Your Internet connection
    /// </summary>
    public static Sid CapabilityInternetClient => GetKnownSid(KnownSidValue.CapabilityInternetClient);

    /// <summary>
    /// APPLICATION PACKAGE AUTHORITY\Your Internet connection, including incoming connections from the Internet
    /// </summary>
    public static Sid CapabilityInternetClientServer => GetKnownSid(KnownSidValue.CapabilityInternetClientServer);

    /// <summary>
    /// APPLICATION PACKAGE AUTHORITY\Your home or work networks
    /// </summary>
    public static Sid CapabilityPrivateNetworkClientServer => GetKnownSid(KnownSidValue.CapabilityPrivateNetworkClientServer);

    /// <summary>
    /// APPLICATION PACKAGE AUTHORITY\Your pictures library
    /// </summary>
    public static Sid CapabilityPicturesLibrary => GetKnownSid(KnownSidValue.CapabilityPicturesLibrary);

    /// <summary>
    /// APPLICATION PACKAGE AUTHORITY\Your videos library
    /// </summary>
    public static Sid CapabilityVideosLibrary => GetKnownSid(KnownSidValue.CapabilityVideosLibrary);

    /// <summary>
    /// APPLICATION PACKAGE AUTHORITY\Your music library
    /// </summary>
    public static Sid CapabilityMusicLibrary => GetKnownSid(KnownSidValue.CapabilityMusicLibrary);

    /// <summary>
    /// APPLICATION PACKAGE AUTHORITY\Your documents library
    /// </summary>
    public static Sid CapabilityDocumentsLibrary => GetKnownSid(KnownSidValue.CapabilityDocumentsLibrary);

    /// <summary>
    /// APPLICATION PACKAGE AUTHORITY\Your Windows credentials
    /// </summary>
    public static Sid CapabilityEnterpriseAuthentication => GetKnownSid(KnownSidValue.CapabilityEnterpriseAuthentication);

    /// <summary>
    /// APPLICATION PACKAGE AUTHORITY\Software and hardware certificates or a smart card
    /// </summary>
    public static Sid CapabilitySharedUserCertificates => GetKnownSid(KnownSidValue.CapabilitySharedUserCertificates);

    /// <summary>
    /// APPLICATION PACKAGE AUTHORITY\Removable storage
    /// </summary>
    public static Sid CapabilityRemovableStorage => GetKnownSid(KnownSidValue.CapabilityRemovableStorage);

    /// <summary>
    /// APPLICATION PACKAGE AUTHORITY\Your Appointments
    /// </summary>
    public static Sid CapabilityAppointments => GetKnownSid(KnownSidValue.CapabilityAppointments);

    /// <summary>
    /// APPLICATION PACKAGE AUTHORITY\Your Contacts
    /// </summary>
    public static Sid CapabilityContacts => GetKnownSid(KnownSidValue.CapabilityContacts);

    /// <summary>
    /// APPLICATION PACKAGE AUTHORITY\Internet Explorer
    /// </summary>
    public static Sid CapabilityInternetExplorer => GetKnownSid(KnownSidValue.CapabilityInternetExplorer);

    /// <summary>
    /// Constrained Impersonation Capability
    /// </summary>
    public static Sid CapabilityConstrainedImpersonation => GetKnownSid(KnownSidValue.CapabilityConstrainedImpersonation);

    private static Sid GetCapabilitySid(params uint[] rids)
    {
        List<uint> capability = new()
        {
            3
        };
        capability.AddRange(rids);
        return new Sid(SecurityAuthority.Package, capability.ToArray());
    }

    /// <summary>
    /// Get a known SID based on a specific enumeration.
    /// </summary>
    /// <param name="sid">The enumerated sid value.</param>
    /// <returns></returns>
    public static Sid GetKnownSid(KnownSidValue sid)
    {
        return sid switch
        {
            KnownSidValue.Null => new Sid(SecurityAuthority.Null, 0),
            KnownSidValue.World => new Sid(SecurityAuthority.World, 0),
            KnownSidValue.Local => new Sid(SecurityAuthority.Local, 0),
            KnownSidValue.CreatorOwner => new Sid(SecurityAuthority.Creator, 0),
            KnownSidValue.CreatorGroup => new Sid(SecurityAuthority.Creator, 1),
            KnownSidValue.CreatorOwnerServer => new Sid(SecurityAuthority.Creator, 2),
            KnownSidValue.CreatorGroupServer => new Sid(SecurityAuthority.Creator, 3),
            KnownSidValue.OwnerRights => new Sid(SecurityAuthority.Creator, 4),
            KnownSidValue.Dialup => new Sid(SecurityAuthority.Nt, 1),
            KnownSidValue.Network => new Sid(SecurityAuthority.Nt, 2),
            KnownSidValue.Batch => new Sid(SecurityAuthority.Nt, 3),
            KnownSidValue.Interactive => new Sid(SecurityAuthority.Nt, 4),
            KnownSidValue.Service => new Sid(SecurityAuthority.Nt, 6),
            KnownSidValue.Anonymous => new Sid(SecurityAuthority.Nt, 7),
            KnownSidValue.Proxy => new Sid(SecurityAuthority.Nt, 8),
            KnownSidValue.Self => new Sid(SecurityAuthority.Nt, 10),
            KnownSidValue.AuthenticatedUsers => new Sid(SecurityAuthority.Nt, 11),
            KnownSidValue.Restricted => new Sid(SecurityAuthority.Nt, 12),
            KnownSidValue.LocalSystem => new Sid(SecurityAuthority.Nt, 18),
            KnownSidValue.LocalService => new Sid(SecurityAuthority.Nt, 19),
            KnownSidValue.NetworkService => new Sid(SecurityAuthority.Nt, 20),
            KnownSidValue.Builtin => new Sid(SecurityAuthority.Nt, 32),
            KnownSidValue.WriteRestricted => new Sid(SecurityAuthority.Nt, 33),
            KnownSidValue.AllApplicationPackages => new Sid(SecurityAuthority.Package, 2, 1),
            KnownSidValue.AllRestrictedApplicationPackages => new Sid(SecurityAuthority.Package, 2, 2),
            KnownSidValue.TrustedInstaller => NtSecurity.GetServiceSid("TrustedInstaller"),
            KnownSidValue.BuiltinUsers => new Sid(SecurityAuthority.Nt, 32, 545),
            KnownSidValue.BuiltinAdministrators => new Sid(SecurityAuthority.Nt, 32, 544),
            KnownSidValue.CapabilityInternetClient => GetCapabilitySid(1),
            KnownSidValue.CapabilityInternetClientServer => GetCapabilitySid(2),
            KnownSidValue.CapabilityPrivateNetworkClientServer => GetCapabilitySid(3),
            KnownSidValue.CapabilityPicturesLibrary => GetCapabilitySid(4),
            KnownSidValue.CapabilityVideosLibrary => GetCapabilitySid(5),
            KnownSidValue.CapabilityMusicLibrary => GetCapabilitySid(6),
            KnownSidValue.CapabilityDocumentsLibrary => GetCapabilitySid(7),
            KnownSidValue.CapabilityEnterpriseAuthentication => GetCapabilitySid(8),
            KnownSidValue.CapabilitySharedUserCertificates => GetCapabilitySid(9),
            KnownSidValue.CapabilityRemovableStorage => GetCapabilitySid(10),
            KnownSidValue.CapabilityAppointments => GetCapabilitySid(11),
            KnownSidValue.CapabilityContacts => GetCapabilitySid(12),
            KnownSidValue.CapabilityInternetExplorer => GetCapabilitySid(4096),
            KnownSidValue.CapabilityConstrainedImpersonation => NtSecurity.GetCapabilitySid("constrainedImpersonation"),
            _ => throw new ArgumentException("Unknown SID type"),
        };
    }
}