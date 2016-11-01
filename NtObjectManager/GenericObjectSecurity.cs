//  Copyright 2016 Google Inc. All Rights Reserved.
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

using NtApiDotNet;
using System.Runtime.InteropServices;
using System.Security.AccessControl;

namespace NtObjectManager
{
    /// <summary>
    /// Generic object security which takes an integer access mask.
    /// </summary>
    public class GenericObjectSecurity : ObjectSecurity<int>
    {
        /// <summary>
        /// Constructor
        /// </summary>
        public GenericObjectSecurity() : base(false, ResourceType.KernelObject)
        {
        }

        /// <summary>
        /// Constructor taking security descriptor from an object.
        /// </summary>
        /// <param name="obj">The NT object to extract the security descriptor from.</param>
        /// <param name="include_sections">Indicates which bits of the security descriptor you want to include.</param>
        public GenericObjectSecurity(NtObject obj, AccessControlSections include_sections) : base(false, ResourceType.KernelObject, obj.Handle, include_sections)
        {
        }

        internal void PersistHandle(SafeHandle handle)
        {
            base.Persist(handle);
        }
    }
}
