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
    public abstract class NtObjectBaseCmdlet : Cmdlet
    {
        [Parameter(Position = 0)]
        public string Path { get; set; }

        [Parameter]
        public NtObject Root { get; set; }

        [Parameter]
        public AttributeFlags Flags { get; set; }

        [Parameter]
        public SecurityDescriptor SecurityDescriptor { get; set; }

        [Parameter]
        public SecurityQualityOfService SecurityQOS { get; set; }

        [Parameter]
        public SwitchParameter AddToDisposeList { get; set; }

        private ObjectAttributes CreateObjAttributes()
        {
            return new ObjectAttributes(GetPath(), Flags, Root, SecurityQOS, SecurityDescriptor);
        }

        protected NtObjectBaseCmdlet()
        {
            Flags = AttributeFlags.CaseInsensitive;
        }

        protected abstract object CreateObject(ObjectAttributes obj_attributes);

        protected virtual void VerifyParameters()
        {
            string path = GetPath();
            if (path != null)
            {
                if (!path.StartsWith(@"\") && Root == null)
                {
                    throw new ArgumentException("Relative paths with no Root directory are not allowed.");
                }
            }
        }

        protected virtual string GetPath()
        {
            return Path;
        }

        protected override void ProcessRecord()
        {
            VerifyParameters();
            using (ObjectAttributes obja = new ObjectAttributes(GetPath(), Flags, Root, SecurityQOS, SecurityDescriptor))
            {
                object obj = CreateObject(obja);
                if (AddToDisposeList && obj is IDisposable)
                {
                    if (!StackHolder.Add((IDisposable)obj))
                    {
                        WriteWarning("No list on the top of the stack");
                    }
                }

                WriteObject(obj);
            }
        }
    }

    public abstract class NtObjectBaseCmdletWithAccess<T> : NtObjectBaseCmdlet where T : struct, IConvertible
    {
        [Parameter]
        public T Access { get; set; }

        protected NtObjectBaseCmdletWithAccess()
        {
            Access = (T)Enum.ToObject(typeof(T), (uint)GenericAccessRights.MaximumAllowed);
        }
    }

    [Cmdlet(VerbsCommon.Get, "NtObject")]
    public sealed class GetNtObjectCmdlet : NtObjectBaseCmdletWithAccess<GenericAccessRights>
    {
        [Parameter]
        public string TypeName { get; set; }

        protected override object CreateObject(ObjectAttributes obj_attributes)
        {
            return NtObject.OpenWithType(TypeName, Path, Root, Access);
        }
    }

    [Cmdlet(VerbsCommon.New, "SecurityDescriptor")]
    public sealed class NewSecurityDescriptorCmdlet : Cmdlet
    {
        [Parameter]
        public bool NullDacl { get; set; }
        [Parameter]
        public string Sddl { get; set; }
        [Parameter]
        public NtToken Token { get; set; }

        protected override void ProcessRecord()
        {
            SecurityDescriptor sd = null;
            if (!String.IsNullOrWhiteSpace(Sddl))
            {
                sd = new SecurityDescriptor(Sddl);
            }
            else if (Token != null)
            {
                sd = new SecurityDescriptor(Token);
            }
            else
            {
                sd = new SecurityDescriptor();
            }

            sd.Dacl = new Acl();
            sd.Dacl.NullAcl = NullDacl;
            WriteObject(sd);
        }
    }
}
