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

// NOTE: This file is a modified version of NdrParser.cs from OleViewDotNet
// https://github.com/tyranid/oleviewdotnet. It's been relicensed from GPLv3 by
// the original author James Forshaw to be used under the Apache License for this
// project.

using System;
using System.IO;
using NtCoreLib.Ndr.Formatter;

namespace NtCoreLib.Ndr.Dce;

#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
[Serializable]
public sealed class NdrSystemHandleTypeReference : NdrBaseTypeReference
{
    // IDL is [system_handle(sh_file, 0x1234)]HANDLE

    public NdrSystemHandleResource Resource { get; }
    public uint AccessMask { get; }

    internal NdrSystemHandleTypeReference(BinaryReader reader)
        : base(NdrFormatCharacter.FC_SYSTEM_HANDLE)
    {
        Resource = (NdrSystemHandleResource)reader.ReadByte();
        AccessMask = reader.ReadUInt32();
    }

    private protected override string FormatType(INdrFormatterContext context)
    {
        if (AccessMask != 0)
        {
            object access = Resource switch
            {
                NdrSystemHandleResource.Pipe or NdrSystemHandleResource.File => (FileAccessRights)AccessMask,
                NdrSystemHandleResource.Process => (ProcessAccessRights)AccessMask,
                NdrSystemHandleResource.Thread => (ThreadAccessRights)AccessMask,
                NdrSystemHandleResource.Event => (EventAccessRights)AccessMask,
                NdrSystemHandleResource.Job => (JobAccessRights)AccessMask,
                NdrSystemHandleResource.Mutex => (MutantAccessRights)AccessMask,
                NdrSystemHandleResource.RegKey => (KeyAccessRights)AccessMask,
                NdrSystemHandleResource.Section => (SectionAccessRights)AccessMask,
                NdrSystemHandleResource.Semaphore => (SemaphoreAccessRights)AccessMask,
                NdrSystemHandleResource.Token => (TokenAccessRights)AccessMask,
                _ => $"0x{AccessMask:X}",
            };
            return $"{context.FormatComment("FC_SYSTEM_HANDLE {0}({1})", Resource, access)}HANDLE";
        }
        return $"{context.FormatComment("FC_SYSTEM_HANDLE {0}", Resource)}HANDLE";
    }

    public override int GetSize()
    {
        return IntPtr.Size;
    }
}

#pragma warning restore 1591

