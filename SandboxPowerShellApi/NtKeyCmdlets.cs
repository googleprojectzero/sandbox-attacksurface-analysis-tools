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
    [Cmdlet(VerbsCommon.Get, "NtKey")]
    public class GetNtKeyCmdlet : NtObjectBaseCmdletWithAccess<KeyAccessRights>
    {
        [Parameter(Position = 0, Mandatory = true)]
        new public string Path { get; set; }
        
        protected override string GetPath()
        {
            return Path;
        }

        protected override object CreateObject(ObjectAttributes obj_attributes)
        {
            return NtKey.Open(obj_attributes, Access);
        }
    }

    [Cmdlet(VerbsCommon.New, "NtKey")]
    public sealed class NewNtKeyCmdlet : GetNtKeyCmdlet
    {
        public KeyCreateOptions Options { get; set; }

        protected override object CreateObject(ObjectAttributes obj_attributes)
        {
            return NtKey.Create(obj_attributes, Access, Options);
        }
    }

    [Cmdlet(VerbsCommon.Add, "NtKey")]
    public sealed class AddNtKeyHiveCmdlet : GetNtKeyCmdlet
    {
        [Parameter(Position = 1, Mandatory = true)]
        public string KeyPath { get; set; }

        [Parameter]
        public LoadKeyFlags LoadFlags { get; set; }

        protected override object CreateObject(ObjectAttributes obj_attributes)
        {
            using (ObjectAttributes name = new ObjectAttributes(KeyPath, AttributeFlags.CaseInsensitive))
            {
                return NtKey.LoadKey(name, obj_attributes, LoadFlags, Access);
            }
        }
    }
}
