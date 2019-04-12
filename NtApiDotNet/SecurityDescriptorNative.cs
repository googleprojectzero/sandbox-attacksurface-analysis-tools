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
using System.Runtime.InteropServices;

namespace NtApiDotNet
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct SecurityDescriptorHeader
    {
        public byte Revision;
        public byte Sbz1;
        public SecurityDescriptorControl Control;

        public bool HasFlag(SecurityDescriptorControl control)
        {
            return (control & Control) == control;
        }
    }

    internal interface ISecurityDescriptor
    {
        long GetOwner(long base_address);
        long GetGroup(long base_address);
        long GetSacl(long base_address);
        long GetDacl(long base_address);
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SecurityDescriptorRelative : ISecurityDescriptor
    {
        public SecurityDescriptorHeader Header;
        public int Owner;
        public int Group;
        public int Sacl;
        public int Dacl;

        long ISecurityDescriptor.GetOwner(long base_address)
        {
            if (Owner == 0)
            {
                return 0;
            }

            return base_address + Owner;
        }

        long ISecurityDescriptor.GetGroup(long base_address)
        {
            if (Group == 0)
            {
                return 0;
            }

            return base_address + Group;
        }

        long ISecurityDescriptor.GetSacl(long base_address)
        {
            if (Sacl == 0)
            {
                return 0;
            }

            return base_address + Sacl;
        }

        long ISecurityDescriptor.GetDacl(long base_address)
        {
            if (Dacl == 0)
            {
                return 0;
            }

            return base_address + Dacl;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SecurityDescriptorAbsolute : ISecurityDescriptor
    {
        public SecurityDescriptorHeader Header;
        public IntPtr Owner;
        public IntPtr Group;
        public IntPtr Sacl;
        public IntPtr Dacl;

        long ISecurityDescriptor.GetOwner(long base_address)
        {
            return Owner.ToInt64();
        }

        long ISecurityDescriptor.GetGroup(long base_address)
        {
            return Group.ToInt64();
        }

        long ISecurityDescriptor.GetSacl(long base_address)
        {
            return Sacl.ToInt64();
        }

        long ISecurityDescriptor.GetDacl(long base_address)
        {
            return Dacl.ToInt64();
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SecurityDescriptorAbsolute32 : ISecurityDescriptor
    {
        public SecurityDescriptorHeader Header;
        public int Owner;
        public int Group;
        public int Sacl;
        public int Dacl;

        long ISecurityDescriptor.GetOwner(long base_address)
        {
            return Owner;
        }

        long ISecurityDescriptor.GetGroup(long base_address)
        {
            return Group;
        }

        long ISecurityDescriptor.GetSacl(long base_address)
        {
            return Sacl;
        }

        long ISecurityDescriptor.GetDacl(long base_address)
        {
            return Dacl;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SidHeader
    {
        public byte Revision;
        public byte RidCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct AclHeader
    {
        public byte AclRevision;
        public byte Sbz1;
        public ushort AclSize;
        public ushort AceCount;
        public ushort Sbz2;
    }
}
