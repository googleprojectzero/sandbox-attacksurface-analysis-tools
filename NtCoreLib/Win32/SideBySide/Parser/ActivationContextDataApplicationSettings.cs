//  Copyright 2023 Google LLC. All Rights Reserved.
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
//
//  Note this is relicensed from OleViewDotNet by the author.

using NtCoreLib.Native.SafeBuffers;
using NtCoreLib.Win32.SideBySide.Interop;

namespace NtCoreLib.Win32.SideBySide.Parser;

/// <summary>
/// Class to represent an application settings entry.
/// </summary>
public sealed class ActivationContextDataApplicationSettings
{
    /// <summary>
    /// The namespace of the setting.
    /// </summary>
    public string Namespace { get; }

    /// <summary>
    /// The name of the setting.
    /// </summary>
    public string Name { get; }

    /// <summary>
    /// The setting value.
    /// </summary>
    public string Value { get; }

    internal ActivationContextDataApplicationSettings(StringSectionEntry<ACTIVATION_CONTEXT_DATA_APPLICATION_SETTINGS> entry, 
        SafeBufferGeneric handle)
    {
        Namespace = handle.ReadString(entry.Offset + entry.Entry.SettingNamespaceOffset, entry.Entry.SettingNamespaceLength);
        Name = handle.ReadString(entry.Offset + entry.Entry.SettingNameOffset, entry.Entry.SettingNameLength);
        Value = handle.ReadString(entry.Offset + entry.Entry.SettingValueOffset, entry.Entry.SettingValueLength);
    }
}
