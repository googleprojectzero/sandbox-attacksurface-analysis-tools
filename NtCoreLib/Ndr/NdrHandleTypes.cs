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

namespace NtApiDotNet.Ndr
{
#pragma warning disable 1591
    [Serializable]
    public enum NdrSystemHandleResource
    {
        File = 0,
        Semaphore = 1,
        Event = 2,
        Mutex = 3,
        Process = 4,
        Token = 5,
        Section = 6,
        RegKey = 7,
        Thread = 8,
        Composition = 9,
        Socket = 10,
        Job = 11,
        Pipe = 12
    }

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

        internal override string FormatType(INdrFormatterInternal context)
        {
            if (AccessMask != 0)
            {
                object access = null;
                switch (Resource)
                {
                    case NdrSystemHandleResource.Pipe:
                    case NdrSystemHandleResource.File:
                        access = (FileAccessRights)AccessMask;
                        break;
                    case NdrSystemHandleResource.Process:
                        access = (ProcessAccessRights)AccessMask;
                        break;
                    case NdrSystemHandleResource.Thread:
                        access = (ThreadAccessRights)AccessMask;
                        break;
                    case NdrSystemHandleResource.Event:
                        access = (EventAccessRights)AccessMask;
                        break;
                    case NdrSystemHandleResource.Job:
                        access = (JobAccessRights)AccessMask;
                        break;
                    case NdrSystemHandleResource.Mutex:
                        access = (MutantAccessRights)AccessMask;
                        break;
                    case NdrSystemHandleResource.RegKey:
                        access = (KeyAccessRights)AccessMask;
                        break;
                    case NdrSystemHandleResource.Section:
                        access = (SectionAccessRights)AccessMask;
                        break;
                    case NdrSystemHandleResource.Semaphore:
                        access = (SemaphoreAccessRights)AccessMask;
                        break;
                    case NdrSystemHandleResource.Token:
                        access = (TokenAccessRights)AccessMask;
                        break;
                    default:
                        access = $"0x{AccessMask:X}";
                        break;
                }

                return $"{context.FormatComment("FC_SYSTEM_HANDLE {0}({1})", Resource, access)} HANDLE";
            }
            return $"{context.FormatComment("FC_SYSTEM_HANDLE {0}", Resource)} HANDLE";
        }

        public override int GetSize()
        {
            return IntPtr.Size;
        }
    }

    [Serializable]
    public class NdrHandleTypeReference : NdrBaseTypeReference
    {
        internal NdrHandleTypeReference(NdrFormatCharacter format)
            : base(format)
        {
        }

        internal override string FormatType(INdrFormatterInternal context)
        {
            return $"{context.FormatComment(Format.ToString())} {context.SimpleTypeToName(Format)}";
        }
    }

#pragma warning restore 1591
}
