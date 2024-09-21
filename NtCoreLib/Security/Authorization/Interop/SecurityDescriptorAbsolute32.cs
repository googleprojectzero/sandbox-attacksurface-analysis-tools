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

using System.Runtime.InteropServices;

namespace NtCoreLib.Security.Authorization.Interop;

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

#pragma warning restore 1591

