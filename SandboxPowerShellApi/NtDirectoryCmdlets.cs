//  Copyright 2016 Google Inc. All Rights Reserved.
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//  http ://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

using NtApiDotNet;
using System.Management.Automation;

namespace SandboxPowerShellApi
{
    /// <summary>
    /// <para type="synopsis">Open a NT object directory by path.</para>
    /// <para type="description">This cmdlet opens an existing NT object directory.</para>
    /// <para type="description">Also part of the longer cmdlet description.</para>
    /// </summary>
    [Cmdlet(VerbsCommon.Get, "NtDirectory")]
    public class GetNtDirectoryCmdlet : NtObjectBaseCmdletWithAccess<DirectoryAccessRights>
    {
        [Parameter]
        public string PrivateNamespaceDescriptor { get; set; }

        protected override string GetPath()
        {
            if (PrivateNamespaceDescriptor != null)
            {
                return null;
            }
            else
            {
                return base.GetPath();
            }
        }

        protected override object CreateObject(ObjectAttributes obj_attributes)
        {
            if (PrivateNamespaceDescriptor != null)
            {
                using (BoundaryDescriptor descriptor = BoundaryDescriptor.CreateFromString(PrivateNamespaceDescriptor))
                {
                    return NtDirectory.OpenPrivateNamespace(obj_attributes, descriptor, Access);
                }
            }
            else
            {
                return NtDirectory.Open(obj_attributes, Access);
            }
        }
    }
    
    [Cmdlet(VerbsCommon.New, "NtDirectory")]
    public sealed class NewNtDirectoryCmdlet : GetNtDirectoryCmdlet
    {
        [Parameter]
        public NtDirectory ShadowDirectory { get; set; }

        protected override object CreateObject(ObjectAttributes obj_attributes)
        {
            if (PrivateNamespaceDescriptor != null)
            {
                using (BoundaryDescriptor descriptor = BoundaryDescriptor.CreateFromString(PrivateNamespaceDescriptor))
                {
                    return NtDirectory.CreatePrivateNamespace(obj_attributes, descriptor, Access);
                }
            }
            else
            {
                return NtDirectory.Create(obj_attributes, Access, ShadowDirectory);
            }
        }
    }
}
