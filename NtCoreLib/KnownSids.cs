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

namespace NtApiDotNet
{
    /// <summary>
    /// An enumeration to reference a known SID.
    /// </summary>
    public enum KnownSidValue
    {
        /// <summary>
        /// NULL SID
        /// </summary>
        Null,

        /// <summary>
        /// Everyone SID
        /// </summary>
        World,

        /// <summary>
        /// Local user SID
        /// </summary>
        Local,

        /// <summary>
        /// CREATOR OWNER SID
        /// </summary>
        CreatorOwner,

        /// <summary>
        /// CREATOR GROUP SID
        /// </summary>
        CreatorGroup,

        /// <summary>
        /// CREATOR OWNER SERVER SID
        /// </summary>
        CreatorOwnerServer,

        /// <summary>
        /// CREATOR OWNER SERVER SID
        /// </summary>
        CreatorGroupServer,

        /// <summary>
        /// Service SID
        /// </summary>
        Service,

        /// <summary>
        /// ANONYMOUS LOGON SID
        /// </summary>
        Anonymous,

        /// <summary>
        /// Authenticated Users SID
        /// </summary>
        AuthenticatedUsers,

        /// <summary>
        /// RESTRICTED SID
        /// </summary>
        Restricted,

        /// <summary>
        /// LOCAL SYSTEM SID
        /// </summary>
        LocalSystem,

        /// <summary>
        /// LOCAL SERVICE SID
        /// </summary>
        LocalService,

        /// <summary>
        /// NETWORK SERVICE SID
        /// </summary>
        NetworkService,

        /// <summary>
        /// APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES SID
        /// </summary>
        AllApplicationPackages,

        /// <summary>
        /// APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES
        /// </summary>
        AllRestrictedApplicationPackages,

        /// <summary>
        /// NT SERVICE\TrustedInstaller
        /// </summary>
        TrustedInstaller,

        /// <summary>
        /// BUILTIN\Users
        /// </summary>
        BuiltinUsers,

        /// <summary>
        /// BUILTIN\Administrators
        /// </summary>
        BuiltinAdministrators,

        /// <summary>
        /// APPLICATION PACKAGE AUTHORITY\Your Internet connection
        /// </summary>
        CapabilityInternetClient,

        /// <summary>
        /// APPLICATION PACKAGE AUTHORITY\Your Internet connection, including incoming connections from the Internet
        /// </summary>
        CapabilityInternetClientServer,

        /// <summary>
        /// APPLICATION PACKAGE AUTHORITY\Your home or work networks
        /// </summary>
        CapabilityPrivateNetworkClientServer,

        /// <summary>
        /// APPLICATION PACKAGE AUTHORITY\Your pictures library
        /// </summary>
        CapabilityPicturesLibrary,

        /// <summary>
        /// APPLICATION PACKAGE AUTHORITY\Your videos library
        /// </summary>
        CapabilityVideosLibrary,

        /// <summary>
        /// APPLICATION PACKAGE AUTHORITY\Your music library
        /// </summary>
        CapabilityMusicLibrary,

        /// <summary>
        /// APPLICATION PACKAGE AUTHORITY\Your documents library
        /// </summary>
        CapabilityDocumentsLibrary,

        /// <summary>
        /// APPLICATION PACKAGE AUTHORITY\Your Windows credentials
        /// </summary>
        CapabilityEnterpriseAuthentication,

        /// <summary>
        /// APPLICATION PACKAGE AUTHORITY\Software and hardware certificates or a smart card
        /// </summary>
        CapabilitySharedUserCertificates,

        /// <summary>
        /// APPLICATION PACKAGE AUTHORITY\Removable storage
        /// </summary>
        CapabilityRemovableStorage,

        /// <summary>
        /// APPLICATION PACKAGE AUTHORITY\Your Appointments
        /// </summary>
        CapabilityAppointments,

        /// <summary>
        /// APPLICATION PACKAGE AUTHORITY\Your Contacts
        /// </summary>
        CapabilityContacts,

        /// <summary>
        /// APPLICATION PACKAGE AUTHORITY\Internet Explorer
        /// </summary>
        CapabilityInternetExplorer,

        /// <summary>
        /// Constrained Impersonation Capability
        /// </summary>
        CapabilityConstrainedImpersonation,

        /// <summary>
        /// OWNER RIGHTS
        /// </summary>
        OwnerRights,

        /// <summary>
        /// NT AUTHORITY\SELF
        /// </summary>
        Self,

        /// <summary>
        /// NT AUTHORITY\WRITE RESTRICTED
        /// </summary>
        WriteRestricted,

        /// <summary>
        /// BUILTIN\BUILTIN
        /// </summary>
        Builtin,

        /// <summary>
        /// NT AUTHORITY\INTERACTIVE
        /// </summary>
        Interactive,

        /// <summary>
        /// NT AUTHORITY\DIALUP
        /// </summary>
        Dialup,

        /// <summary>
        /// NT AUTHORITY\NETWORK
        /// </summary>
        Network,

        /// <summary>
        /// NT AUTHORITY\BATCH
        /// </summary>
        Batch,

        /// <summary>
        /// NT AUTHORITY\PROXY
        /// </summary>
        Proxy,
    }

    /// <summary>
    /// Static methods to get some known SIDs.
    /// </summary>
    public static class KnownSids
    {
        /// <summary>
        /// NULL SID
        /// </summary>
        public static Sid Null { get { return GetKnownSid(KnownSidValue.Null); } }

        /// <summary>
        /// Everyone SID
        /// </summary>
        public static Sid World { get { return GetKnownSid(KnownSidValue.World); } }

        /// <summary>
        /// Local user SID
        /// </summary>
        public static Sid Local { get { return GetKnownSid(KnownSidValue.Local); } }

        /// <summary>
        /// CREATOR OWNER SID
        /// </summary>
        public static Sid CreatorOwner { get { return GetKnownSid(KnownSidValue.CreatorOwner); } }

        /// <summary>
        /// CREATOR GROUP SID
        /// </summary>
        public static Sid CreatorGroup { get { return GetKnownSid(KnownSidValue.CreatorGroup); } }

        /// <summary>
        /// CREATOR OWNER SERVER SID
        /// </summary>
        public static Sid CreatorOwnerServer { get { return GetKnownSid(KnownSidValue.CreatorOwnerServer); } }

        /// <summary>
        /// CREATOR OWNER SERVER SID
        /// </summary>
        public static Sid CreatorGroupServer { get { return GetKnownSid(KnownSidValue.CreatorGroupServer); } }

        /// <summary>
        /// Service SID
        /// </summary>
        public static Sid Service { get { return GetKnownSid(KnownSidValue.Service); } }

        /// <summary>
        /// ANONYMOUS LOGON SID
        /// </summary>
        public static Sid Anonymous { get { return GetKnownSid(KnownSidValue.Anonymous); } }

        /// <summary>
        /// Authenticated Users SID
        /// </summary>
        public static Sid AuthenticatedUsers { get { return GetKnownSid(KnownSidValue.AuthenticatedUsers); } }

        /// <summary>
        /// RESTRICTED SID
        /// </summary>
        public static Sid Restricted { get { return GetKnownSid(KnownSidValue.Restricted); } }

        /// <summary>
        /// NT AUTHORITY\WRITE RESTRICTED
        /// </summary>
        public static Sid WriteRestricted { get { return GetKnownSid(KnownSidValue.WriteRestricted); } }

        /// <summary>
        /// BUILTIN\BUILTIN
        /// </summary>
        public static Sid Builtin { get { return GetKnownSid(KnownSidValue.Builtin); } }

        /// <summary>
        /// NT AUTHORITY\INTERACTIVE
        /// </summary>
        public static Sid Interactive { get { return GetKnownSid(KnownSidValue.Interactive); } }

        /// <summary>
        /// NT AUTHORITY\DIALUP
        /// </summary>
        public static Sid Dialup { get { return GetKnownSid(KnownSidValue.Dialup); } }

        /// <summary>
        /// NT AUTHORITY\NETWORK
        /// </summary>
        public static Sid Network { get { return GetKnownSid(KnownSidValue.Network); } }

        /// <summary>
        /// NT AUTHORITY\BATCH
        /// </summary>
        public static Sid Batch { get { return GetKnownSid(KnownSidValue.Batch); } }

        /// <summary>
        /// NT AUTHORITY\PROXY
        /// </summary>
        public static Sid Proxy { get { return GetKnownSid(KnownSidValue.Proxy); } }

        /// <summary>
        /// LOCAL SYSTEM SID
        /// </summary>
        public static Sid LocalSystem { get { return GetKnownSid(KnownSidValue.LocalSystem); } }

        /// <summary>
        /// LOCAL SERVICE SID
        /// </summary>
        public static Sid LocalService { get { return GetKnownSid(KnownSidValue.LocalService); } }

        /// <summary>
        /// NETWORK SERVICE SID
        /// </summary>
        public static Sid NetworkService { get { return GetKnownSid(KnownSidValue.NetworkService); } }

        /// <summary>
        /// APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES SID
        /// </summary>
        public static Sid AllApplicationPackages { get { return GetKnownSid(KnownSidValue.AllApplicationPackages); } }

        /// <summary>
        /// APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES
        /// </summary>
        public static Sid AllRestrictedApplicationPackages { get { return GetKnownSid(KnownSidValue.AllRestrictedApplicationPackages); } }

        /// <summary>
        /// NT SERVICE\TrustedInstaller
        /// </summary>
        public static Sid TrustedInstaller { get { return GetKnownSid(KnownSidValue.TrustedInstaller); } }

        /// <summary>
        /// BUILTIN\Users
        /// </summary>
        public static Sid BuiltinUsers { get { return GetKnownSid(KnownSidValue.BuiltinUsers); } }

        /// <summary>
        /// BUILTIN\Administrators
        /// </summary>
        public static Sid BuiltinAdministrators { get { return GetKnownSid(KnownSidValue.BuiltinAdministrators); } }

        /// <summary>
        /// APPLICATION PACKAGE AUTHORITY\Your Internet connection
        /// </summary>
        public static Sid CapabilityInternetClient { get { return GetKnownSid(KnownSidValue.CapabilityInternetClient); } }

        /// <summary>
        /// APPLICATION PACKAGE AUTHORITY\Your Internet connection, including incoming connections from the Internet
        /// </summary>
        public static Sid CapabilityInternetClientServer { get { return GetKnownSid(KnownSidValue.CapabilityInternetClientServer); } }

        /// <summary>
        /// APPLICATION PACKAGE AUTHORITY\Your home or work networks
        /// </summary>
        public static Sid CapabilityPrivateNetworkClientServer { get { return GetKnownSid(KnownSidValue.CapabilityPrivateNetworkClientServer); } }

        /// <summary>
        /// APPLICATION PACKAGE AUTHORITY\Your pictures library
        /// </summary>
        public static Sid CapabilityPicturesLibrary { get { return GetKnownSid(KnownSidValue.CapabilityPicturesLibrary); } }

        /// <summary>
        /// APPLICATION PACKAGE AUTHORITY\Your videos library
        /// </summary>
        public static Sid CapabilityVideosLibrary { get { return GetKnownSid(KnownSidValue.CapabilityVideosLibrary); } }

        /// <summary>
        /// APPLICATION PACKAGE AUTHORITY\Your music library
        /// </summary>
        public static Sid CapabilityMusicLibrary { get { return GetKnownSid(KnownSidValue.CapabilityMusicLibrary); } }

        /// <summary>
        /// APPLICATION PACKAGE AUTHORITY\Your documents library
        /// </summary>
        public static Sid CapabilityDocumentsLibrary { get { return GetKnownSid(KnownSidValue.CapabilityDocumentsLibrary); } }

        /// <summary>
        /// APPLICATION PACKAGE AUTHORITY\Your Windows credentials
        /// </summary>
        public static Sid CapabilityEnterpriseAuthentication { get { return GetKnownSid(KnownSidValue.CapabilityEnterpriseAuthentication); } }

        /// <summary>
        /// APPLICATION PACKAGE AUTHORITY\Software and hardware certificates or a smart card
        /// </summary>
        public static Sid CapabilitySharedUserCertificates { get { return GetKnownSid(KnownSidValue.CapabilitySharedUserCertificates); } }

        /// <summary>
        /// APPLICATION PACKAGE AUTHORITY\Removable storage
        /// </summary>
        public static Sid CapabilityRemovableStorage { get { return GetKnownSid(KnownSidValue.CapabilityRemovableStorage); } }

        /// <summary>
        /// APPLICATION PACKAGE AUTHORITY\Your Appointments
        /// </summary>
        public static Sid CapabilityAppointments { get { return GetKnownSid(KnownSidValue.CapabilityAppointments); } }

        /// <summary>
        /// APPLICATION PACKAGE AUTHORITY\Your Contacts
        /// </summary>
        public static Sid CapabilityContacts { get { return GetKnownSid(KnownSidValue.CapabilityContacts); } }

        /// <summary>
        /// APPLICATION PACKAGE AUTHORITY\Internet Explorer
        /// </summary>
        public static Sid CapabilityInternetExplorer
        {
            get { return GetKnownSid(KnownSidValue.CapabilityInternetExplorer); }
        }

        /// <summary>
        /// Constrained Impersonation Capability
        /// </summary>
        public static Sid CapabilityConstrainedImpersonation
        {
            get { return GetKnownSid(KnownSidValue.CapabilityConstrainedImpersonation); }
        }

        private static Sid GetCapabilitySid(params uint[] rids)
        {
            List<uint> capability = new List<uint>();
            capability.Add(3);
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
            switch (sid)
            {
                case KnownSidValue.Null: return new Sid(SecurityAuthority.Null, 0);
                case KnownSidValue.World: return new Sid(SecurityAuthority.World, 0);
                case KnownSidValue.Local: return new Sid(SecurityAuthority.Local, 0);
                case KnownSidValue.CreatorOwner: return new Sid(SecurityAuthority.Creator, 0);
                case KnownSidValue.CreatorGroup: return new Sid(SecurityAuthority.Creator, 1);
                case KnownSidValue.CreatorOwnerServer: return new Sid(SecurityAuthority.Creator, 2);
                case KnownSidValue.CreatorGroupServer: return new Sid(SecurityAuthority.Creator, 3);
                case KnownSidValue.OwnerRights: return new Sid(SecurityAuthority.Creator, 4);
                case KnownSidValue.Dialup: return new Sid(SecurityAuthority.Nt, 1);
                case KnownSidValue.Network: return new Sid(SecurityAuthority.Nt, 2);
                case KnownSidValue.Batch: return new Sid(SecurityAuthority.Nt, 3);
                case KnownSidValue.Interactive: return new Sid(SecurityAuthority.Nt, 4);
                case KnownSidValue.Service: return new Sid(SecurityAuthority.Nt, 6);
                case KnownSidValue.Anonymous: return new Sid(SecurityAuthority.Nt, 7);
                case KnownSidValue.Proxy: return new Sid(SecurityAuthority.Nt, 8);
                case KnownSidValue.Self: return new Sid(SecurityAuthority.Nt, 10);
                case KnownSidValue.AuthenticatedUsers: return new Sid(SecurityAuthority.Nt, 11);
                case KnownSidValue.Restricted: return new Sid(SecurityAuthority.Nt, 12);
                case KnownSidValue.LocalSystem: return new Sid(SecurityAuthority.Nt, 18);
                case KnownSidValue.LocalService: return new Sid(SecurityAuthority.Nt, 19);
                case KnownSidValue.NetworkService: return new Sid(SecurityAuthority.Nt, 20);
                case KnownSidValue.Builtin: return new Sid(SecurityAuthority.Nt, 32);
                case KnownSidValue.WriteRestricted: return new Sid(SecurityAuthority.Nt, 33);
                case KnownSidValue.AllApplicationPackages: return new Sid(SecurityAuthority.Package, 2, 1);
                case KnownSidValue.AllRestrictedApplicationPackages: return new Sid(SecurityAuthority.Package, 2, 2);
                case KnownSidValue.TrustedInstaller: return NtSecurity.GetServiceSid("TrustedInstaller");
                case KnownSidValue.BuiltinUsers: return new Sid(SecurityAuthority.Nt, 32, 545);
                case KnownSidValue.BuiltinAdministrators: return new Sid(SecurityAuthority.Nt, 32, 544);
                case KnownSidValue.CapabilityInternetClient: return GetCapabilitySid(1);
                case KnownSidValue.CapabilityInternetClientServer: return GetCapabilitySid(2);
                case KnownSidValue.CapabilityPrivateNetworkClientServer: return GetCapabilitySid(3);
                case KnownSidValue.CapabilityPicturesLibrary: return GetCapabilitySid(4);
                case KnownSidValue.CapabilityVideosLibrary: return GetCapabilitySid(5);
                case KnownSidValue.CapabilityMusicLibrary: return GetCapabilitySid(6);
                case KnownSidValue.CapabilityDocumentsLibrary: return GetCapabilitySid(7);
                case KnownSidValue.CapabilityEnterpriseAuthentication: return GetCapabilitySid(8);
                case KnownSidValue.CapabilitySharedUserCertificates: return GetCapabilitySid(9);
                case KnownSidValue.CapabilityRemovableStorage: return GetCapabilitySid(10);
                case KnownSidValue.CapabilityAppointments: return GetCapabilitySid(11);
                case KnownSidValue.CapabilityContacts: return GetCapabilitySid(12);
                case KnownSidValue.CapabilityInternetExplorer: return GetCapabilitySid(4096);
                case KnownSidValue.CapabilityConstrainedImpersonation:
                    return NtSecurity.GetCapabilitySid("constrainedImpersonation");
                default:
                    throw new ArgumentException("Unknown SID type");
            }
        }
    }
}