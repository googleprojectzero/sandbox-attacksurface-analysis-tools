//  Copyright 2016 Google Inc. All Rights Reserved.
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
using NtCoreLib.Win32.Security.Authorization.AclUI;
using System;
using System.Runtime.InteropServices;

namespace NtCoreLib.Win32.Security.Interop;

[Guid("965FC360-16FF-11d0-91CB-00AA00BBB723"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown), ComVisible(true)]
internal interface ISecurityInformation
{
    // *** ISecurityInformation methods ***
    void GetObjectInformation(IntPtr pObjectInfo);
    void GetSecurity(SecurityInformation RequestedInformation,
                    out IntPtr ppSecurityDescriptor,
                    [MarshalAs(UnmanagedType.Bool)] bool fDefault);

    void SetSecurity(SecurityInformation SecurityInformation,
                    IntPtr pSecurityDescriptor);

    void GetAccessRights(ref Guid pguidObjectType,
                        SiObjectInfoFlags dwFlags, // SI_EDIT_AUDITS, SI_EDIT_PROPERTIES
                        out IntPtr ppAccess,
                        out uint pcAccesses,
                        out uint piDefaultAccess);

    void MapGeneric(ref Guid pguidObjectType,
                    IntPtr pAceFlags,
                    ref AccessMask pMask);

    void GetInheritTypes(out IntPtr ppInheritTypes,
                        out uint pcInheritTypes);
    void PropertySheetPageCallback(IntPtr hwnd, uint uMsg, int uPage);
}
