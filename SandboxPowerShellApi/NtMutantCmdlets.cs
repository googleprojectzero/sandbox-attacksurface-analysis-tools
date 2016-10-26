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
    [Cmdlet(VerbsCommon.Get, "NtMutant")]
    public sealed class GetNtMutantCmdlet : NtObjectBaseCmdletWithAccess<MutantAccessRights>
    {
        protected override object CreateObject(ObjectAttributes obj_attributes)
        {
            return NtMutant.Open(Path, Root, Access);
        }
    }

    [Cmdlet(VerbsCommon.New, "NtMutant")]
    public sealed class NewNtMutantCmdlet : NtObjectBaseCmdletWithAccess<MutantAccessRights>
    {
        [Parameter]
        public SwitchParameter InitialOwner { get; set; }

        protected override object CreateObject(ObjectAttributes obj_attributes)
        {
            return NtMutant.Create(Path, Root, InitialOwner);
        }
    }
}
