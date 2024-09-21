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

namespace NtCoreLib.Security.Authorization;

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
