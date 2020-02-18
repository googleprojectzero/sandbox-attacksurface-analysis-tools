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

using System.Runtime.InteropServices;

namespace NtApiDotNet
{
    /// <summary>
    /// Class representing a NT SymbolicLink object
    /// </summary>
    [NtType("SymbolicLink")]
    public class NtSymbolicLink : NtObjectWithDuplicateAndInfo<NtSymbolicLink, SymbolicLinkAccessRights, SymbolicLinkInformationClass, SymbolicLinkInformationClass>
    {
        #region Constructors
        internal NtSymbolicLink(SafeKernelObjectHandle handle) : base(handle)
        {
        }

        internal sealed class NtTypeFactoryImpl : NtTypeFactoryImplBase
        {
            public NtTypeFactoryImpl() : base(true)
            {
            }

            protected override sealed NtResult<NtSymbolicLink> OpenInternal(ObjectAttributes obj_attributes,
                SymbolicLinkAccessRights desired_access, bool throw_on_error)
            {
                return NtSymbolicLink.Open(obj_attributes, desired_access, throw_on_error);
            }
        }
        #endregion

        #region Static Methods

        /// <summary>
        /// Create a symbolic link object.
        /// </summary>
        /// <param name="path">The path to the object</param>
        /// <param name="root">The root if path is relative</param>
        /// <param name="desired_access">The desired access for the object</param>
        /// <param name="target">The target path</param>
        /// <returns>The opened object</returns>
        public static NtSymbolicLink Create(string path, NtObject root, SymbolicLinkAccessRights desired_access, string target)
        {
            using (ObjectAttributes obja = new ObjectAttributes(path, AttributeFlags.CaseInsensitive, root))
            {
                return Create(obja, desired_access, target);
            }
        }

        /// <summary>
        /// Create a symbolic link object.
        /// </summary>
        /// <param name="object_attributes">The object attributes for the object</param>
        /// <param name="desired_access">The desired access for the object</param>
        /// <param name="target">The target path</param>
        /// <param name="throw_on_error">True to throw an exception on error.</param>
        /// <returns>The NT status code and object result.</returns>
        public static NtResult<NtSymbolicLink> Create(ObjectAttributes object_attributes, SymbolicLinkAccessRights desired_access, string target, bool throw_on_error)
        {
            return NtSystemCalls.NtCreateSymbolicLinkObject(out SafeKernelObjectHandle handle,
                desired_access, object_attributes, new UnicodeString(target)).CreateResult(throw_on_error, () => new NtSymbolicLink(handle));
        }

        /// <summary>
        /// Create a symbolic link object.
        /// </summary>
        /// <param name="object_attributes">The object attributes for the object</param>
        /// <param name="desired_access">The desired access for the object</param>
        /// <param name="target">The target path</param>
        /// <returns>The opened object</returns>
        public static NtSymbolicLink Create(ObjectAttributes object_attributes, SymbolicLinkAccessRights desired_access, string target)
        {
            return Create(object_attributes, desired_access, target, true).Result;
        }

        /// <summary>
        /// Create a symbolic link object.
        /// </summary>
        /// <param name="path">The path to the object</param>
        /// <param name="root">The root if path is relative</param>
        /// <param name="target">The target path</param>
        /// <returns>The opened object</returns>
        public static NtSymbolicLink Create(string path, NtObject root, string target)
        {
            return Create(path, root, SymbolicLinkAccessRights.MaximumAllowed, target);
        }

        /// <summary>
        /// Create a symbolic link object.
        /// </summary>
        /// <param name="path">The path to the object</param>
        /// <param name="target">The target path</param>
        /// <returns>The opened object</returns>
        public static NtSymbolicLink Create(string path, string target)
        {
            return Create(path, null, SymbolicLinkAccessRights.MaximumAllowed, target);
        }

        /// <summary>
        /// Open a symbolic link object.
        /// </summary>
        /// <param name="path">The path to the object</param>
        /// <param name="root">The root if path is relative</param>
        /// <param name="desired_access">The desired access for the object</param>
        /// <returns>The opened object</returns>
        public static NtSymbolicLink Open(string path, NtObject root, SymbolicLinkAccessRights desired_access)
        {
            return Open(path, root, desired_access, true).Result;
        }

        /// <summary>
        /// Open a symbolic link object.
        /// </summary>
        /// <param name="path">The path to the object</param>
        /// <param name="root">The root if path is relative</param>
        /// <param name="desired_access">The desired access for the object</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The opened object</returns>
        public static NtResult<NtSymbolicLink> Open(string path, NtObject root, 
            SymbolicLinkAccessRights desired_access, bool throw_on_error)
        {
            using (ObjectAttributes obja = new ObjectAttributes(path, AttributeFlags.CaseInsensitive, root))
            {
                return Open(obja, desired_access, throw_on_error);
            }
        }

        /// <summary>
        /// Open a symbolic link object.
        /// </summary>
        /// <param name="object_attributes">The object attributes for the object</param>
        /// <param name="desired_access">The desired access for the object</param>
        /// <param name="throw_on_error">True to throw an exception on error.</param>
        /// <returns>The NT status code and object result.</returns>
        public static NtResult<NtSymbolicLink> Open(ObjectAttributes object_attributes, SymbolicLinkAccessRights desired_access, bool throw_on_error)
        {
            return NtSystemCalls.NtOpenSymbolicLinkObject(out SafeKernelObjectHandle handle,
                desired_access, object_attributes).CreateResult(throw_on_error, () => new NtSymbolicLink(handle));
        }

        /// <summary>
        /// Open a symbolic link object.
        /// </summary>
        /// <param name="object_attributes">The object attributes for the object</param>
        /// <param name="desired_access">The desired access for the object</param>
        /// <returns>The opened object</returns>
        public static NtSymbolicLink Open(ObjectAttributes object_attributes, SymbolicLinkAccessRights desired_access)
        {
            return Open(object_attributes, desired_access, true).Result;
        }

        /// <summary>
        /// Open a symbolic link object.
        /// </summary>
        /// <param name="path">The path to the object</param>
        /// <param name="root">The root if path is relative</param>
        /// <returns>The opened object</returns>
        public static NtSymbolicLink Open(string path, NtObject root)
        {
            return Open(path, root, SymbolicLinkAccessRights.MaximumAllowed);
        }

        /// <summary>
        /// Open a symbolic link object.
        /// </summary>
        /// <param name="path">The path to the object</param>
        /// <returns>The opened object</returns>
        public static NtSymbolicLink Open(string path)
        {
            return Open(path, null);
        }

        #endregion

        #region Public Properties
        /// <summary>
        /// Get the symbolic link target.
        /// </summary>
        public string Target => GetTarget(true).Result;
        #endregion

        #region Public Methods

        /// <summary>
        /// Method to set information for this object type.
        /// </summary>
        /// <param name="info_class">The information class.</param>
        /// <param name="buffer">The buffer to set data from.</param>
        /// <returns>The NT status code for the set.</returns>
        public override NtStatus SetInformation(SymbolicLinkInformationClass info_class, SafeBuffer buffer)
        {
            return NtSystemCalls.NtSetInformationSymbolicLink(Handle, info_class, buffer, buffer.GetLength());
        }

        /// <summary>
        /// Set access mask filter.
        /// </summary>
        /// <param name="access_mask">The access mask to set.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        /// <remarks>Needs SeTcbPrivilege.</remarks>
        public NtStatus SetAccessMask(AccessMask access_mask, bool throw_on_error)
        {
            return Set(SymbolicLinkInformationClass.SymbolicLinkAccessMask, 
                access_mask.Access, throw_on_error);
        }

        /// <summary>
        /// Set access mask filter.
        /// </summary>
        /// <param name="access_mask">The access mask to set.</param>
        /// <remarks>Needs SeTcbPrivilege.</remarks>
        public void SetAccessMask(AccessMask access_mask)
        {
            SetAccessMask(access_mask, true);
        }

        /// <summary>
        /// Set as a global link.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        /// <remarks>Needs SeTcbPrivilege.</remarks>
        public NtStatus SetGlobalLink(bool throw_on_error)
        {
            return Set(SymbolicLinkInformationClass.SymbolicLinkGlobalInformation, 1, throw_on_error);
        }

        /// <summary>
        /// Set as a global link.
        /// </summary>
        /// <remarks>Needs SeTcbPrivilege.</remarks>
        public void SetGlobalLink()
        {
            SetGlobalLink(true);
        }

        /// <summary>
        /// Get the symbolic link target path.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The target path.</returns>
        public NtResult<string> GetTarget(bool throw_on_error)
        {
            using (UnicodeStringAllocated ustr = new UnicodeStringAllocated())
            {
                return NtSystemCalls.NtQuerySymbolicLinkObject(Handle, ustr,
                    out int return_length).CreateResult(throw_on_error, () => ustr.ToString());
            }
        }

        #endregion
    }
}
