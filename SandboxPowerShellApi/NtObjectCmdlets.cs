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
    /// <summary>
    /// Base object cmdlet.
    /// </summary>
    public abstract class NtObjectBaseCmdlet : Cmdlet, IDisposable
    {
        /// <summary>
        /// <para type="description">The NT object manager path to the object to use.</para>
        /// </summary>
        [Parameter(Position = 0)]
        public string Path { get; set; }

        /// <summary>
        /// <para type="description">An existing open NT object to use when Path is relative.</para>
        /// </summary>
        [Parameter(ValueFromPipeline = true)]
        public NtObject Root { get; set; }

        /// <summary>
        /// <para type="description">Object Attribute flags used during Open/Create calls.</para>
        /// </summary>
        [Parameter]
        public AttributeFlags Flags { get; set; }

        /// <summary>
        /// <para type="description">Set to provide an explicit security descriptor to a newly created object.</para>
        /// </summary>
        [Parameter]
        public SecurityDescriptor SecurityDescriptor { get; set; }

        /// <summary>
        /// <para type="description">Set to provide an explicit security quality of service when opening files/namedpipes.</para>
        /// </summary>
        [Parameter]
        public SecurityQualityOfService SecurityQualityOfService { get; set; }

        /// <summary>
        /// <para type="description">Automatically add output objects to the top of the dispose list stack.</para>
        /// </summary>
        [Parameter]
        public SwitchParameter AddToDisposeList { get; set; }

        /// <summary>
        /// <para type="description">Automatically close the Root object when this cmdlet finishes processing. Useful for pipelines.</para>
        /// </summary>
        [Parameter]
        public SwitchParameter CloseRoot { get; set; }

        private ObjectAttributes CreateObjAttributes()
        {
            return new ObjectAttributes(GetPath(), Flags, Root, SecurityQualityOfService, SecurityDescriptor);
        }

        /// <summary>
        /// Base constructor.
        /// </summary>
        protected NtObjectBaseCmdlet()
        {
            Flags = AttributeFlags.CaseInsensitive;
        }

        /// <summary>
        /// Method to create an object from a set of object attributes.
        /// </summary>
        /// <param name="obj_attributes">The object attributes to create/open from.</param>
        /// <returns>The newly created object.</returns>
        protected abstract object CreateObject(ObjectAttributes obj_attributes);

        /// <summary>
        /// Verify the parameters, should throw an exception if parameters are invalid.
        /// </summary>
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

        /// <summary>
        /// Virtual method to return the value of the Path variable.
        /// </summary>
        /// <returns>The object path.</returns>
        protected virtual string GetPath()
        {
            return Path;
        }

        /// <summary>
        /// Overridden ProcessRecord method.
        /// </summary>
        protected override void ProcessRecord()
        {
            VerifyParameters();
            using (ObjectAttributes obja = new ObjectAttributes(GetPath(), Flags, Root, SecurityQualityOfService, SecurityDescriptor))
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

        #region IDisposable Support
        private bool disposedValue = false; // To detect redundant calls

        /// <summary>
        /// Dispose object.
        /// </summary>
        protected virtual void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (CloseRoot && Root != null)
                {
                    NtObject obj = Root;
                    Root = null;
                    obj.Close();
                }
                disposedValue = true;
            }
        }

        /// <summary>
        /// Finalizer.
        /// </summary>
         ~NtObjectBaseCmdlet()
        {
            Dispose(false);
        }

        /// <summary>
        /// Dispose object.
        /// </summary>
        void IDisposable.Dispose()
        {            
            Dispose(true);
            GC.SuppressFinalize(this);
        }
        #endregion
    }

    /// <summary>
    /// Base object cmdlet which has an access parameter.
    /// </summary>
    /// <typeparam name="T"></typeparam>
    public abstract class NtObjectBaseCmdletWithAccess<T> : NtObjectBaseCmdlet where T : struct, IConvertible
    {
        /// <summary>
        /// <para type="description">Specify the access rights for a new handle when creating/opening an object.</para>
        /// </summary>
        [Parameter]
        public T Access { get; set; }

        /// <summary>
        /// Constructor.
        /// </summary>
        protected NtObjectBaseCmdletWithAccess()
        {
            Access = (T)Enum.ToObject(typeof(T), (uint)GenericAccessRights.MaximumAllowed);
        }
    }

    /// <summary>
    /// <para type="synopsis">Open an NT object by path.</para>
    /// <para type="description">This cmdlet opens an NT object by its path. The returned object
    /// will be a type specific to the actual underlying NT type.
    /// </para>
    /// </summary>
    /// <para type="link">about_ManagingNtObjectLifetime</para>
    [Cmdlet(VerbsCommon.Get, "NtObject")]
    public sealed class GetNtObjectCmdlet : NtObjectBaseCmdletWithAccess<GenericAccessRights>
    {
        /// <summary>
        /// <para type="description">The type of object will try and be determined automatically, however in cases where this isn't possible the NT type name can be specified here.
        /// This needs to be a value such as Directory, SymbolicLink, Mutant etc.
        /// </para>
        /// </summary>
        [Parameter]
        public string TypeName { get; set; }

        /// <summary>
        /// <para type="description">The NT object manager path to the object to use.</para>
        /// </summary>
        [Parameter(Position = 0, Mandatory = true)]
        new public string Path { get; set; }

        /// <summary>
        /// Overridden GetPath
        /// </summary>
        /// <returns>The path to the object.</returns>
        protected override string GetPath()
        {
            return Path;
        }

        /// <summary>
        /// Method to create an object from a set of object attributes.
        /// </summary>
        /// <param name="obj_attributes">The object attributes to create/open from.</param>
        /// <returns>The newly created object.</returns>
        protected override object CreateObject(ObjectAttributes obj_attributes)
        {
            return NtObject.OpenWithType(TypeName, Path, Root, Access);
        }
    }

    [Cmdlet(VerbsCommon.New, "NtSecurityDescriptor")]
    public sealed class NewNtSecurityDescriptorCmdlet : Cmdlet
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
