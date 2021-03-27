//  Copyright 2021 Google Inc. All Rights Reserved.
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

namespace NtApiDotNet.Win32.Image
{
    /// <summary>
    /// Known image resource types.
    /// </summary>
    public enum WellKnownImageResourceType
    {
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
        Unknown = 0,
        [SDKName("RT_CURSOR")]
        Cursor = 1,
        [SDKName("RT_BITMAP")]
        Bitmap = 2,
        [SDKName("RT_ICON")]
        Icon = 3,
        [SDKName("RT_MENU")]
        Menu = 4,
        [SDKName("RT_DIALOG")]
        Dialog = 5,
        [SDKName("RT_STRING")]
        String = 6,
        [SDKName("RT_FONTDIR")]
        FontDir = 7,
        [SDKName("RT_FONT")]
        Font = 8,
        [SDKName("RT_ACCELERATOR")]
        Accelerator = 9,
        [SDKName("RT_RCDATA")]
        RCData = 10,
        [SDKName("RT_MESSAGETABLE")]
        MessageTable = 11,
        [SDKName("RT_GROUP_CURSOR")]
        GroupCursor = 12,
        [SDKName("RT_GROUP_ICON")]
        GroupIcon = 14,
        [SDKName("RT_VERSION")]
        Version = 16,
        [SDKName("RT_DLGINCLUDE")]
        DlgInclude = 17,
        [SDKName("RT_PLUGPLAY")]
        PlugPlay = 19,
        [SDKName("RT_VXD")]
        VXD = 20,
        [SDKName("RT_ANICURSOR")]
        AniCursor = 21,
        [SDKName("RT_ANIICON")]
        AniIcon = 22,
        [SDKName("RT_HTML")]
        HTML = 23,
        [SDKName("RT_MANIFEST")]
        Manifest = 24
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
    }
}
