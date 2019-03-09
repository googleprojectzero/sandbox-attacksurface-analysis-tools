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

namespace NtApiDotNet
{
    /// <summary>
    /// Class representing a NT SymbolicLink object
    /// </summary>
    [NtType("SymbolicLink")]
    public class NtSymbolicLink : NtObjectWithDuplicate<NtSymbolicLink, SymbolicLinkAccessRights>
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
            using (ObjectAttributes obja = new ObjectAttributes(path, AttributeFlags.CaseInsensitive, root))
            {
                return Open(obja, desired_access);
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
        public string Target
        {
            get
            {
                using (UnicodeStringAllocated ustr = new UnicodeStringAllocated())
                {
                    NtSystemCalls.NtQuerySymbolicLinkObject(Handle, ustr, 
                        out int return_length).ToNtException();
                    return ustr.ToString();
                }
            }
        }
        #endregion
    }
}
