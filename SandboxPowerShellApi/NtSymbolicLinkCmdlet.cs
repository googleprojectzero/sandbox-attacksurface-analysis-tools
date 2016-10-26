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
using System;
using System.Management.Automation;

namespace SandboxPowerShellApi
{
    [Cmdlet(VerbsCommon.Get, "NtSymbolicLink")]
    public class GetNtSymbolicLinkCmdlet : NtObjectBaseCmdletWithAccess<SymbolicLinkAccessRights>
    {   
        public GetNtSymbolicLinkCmdlet()
        {
            Access = SymbolicLinkAccessRights.MaximumAllowed;
        }

        protected override object CreateObject(ObjectAttributes obj_attributes)
        {
            return NtSymbolicLink.Open(obj_attributes, Access);
        }
    }

    [Cmdlet(VerbsCommon.Get, "NtSymbolicLinkTarget")]
    public class GetNtSymbolicLinkTargetCmdlet : NtObjectBaseCmdlet
    {
        [Parameter(Position = 0, Mandatory = true)]
        new public string Path { get; set; }

        protected override string GetPath()
        {
            return Path;
        }

        protected override object CreateObject(ObjectAttributes obj_attributes)
        {
            using (NtSymbolicLink link = NtSymbolicLink.Open(obj_attributes, SymbolicLinkAccessRights.Query))
            {
                return link.Query();
            }
        }
    }

    [Cmdlet(VerbsCommon.New, "NtSymbolicLink")]
    public class NewNtSymbolicLinkCmdlet : NtObjectBaseCmdletWithAccess<SymbolicLinkAccessRights>
    {
        [Parameter(Position = 1, Mandatory = true), AllowEmptyString()]
        public string TargetPath { get; set; }

        protected override object CreateObject(ObjectAttributes obj_attributes)
        {
            if (TargetPath == null)
            {
                throw new ArgumentNullException("TargetPath");
            }

            return NtSymbolicLink.Create(obj_attributes, Access, TargetPath);
        }
    }
    
}
