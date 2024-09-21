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
    /// Class representing a NT Mutant object
    /// </summary>
    [NtType("Mutant")]
    public class NtMutant : NtObjectWithDuplicateAndInfo<NtMutant, MutantAccessRights, MutantInformationClass, MutantInformationClass>
    {
        #region Constructors
        internal NtMutant(SafeKernelObjectHandle handle) : base(handle)
        {
        }

        internal sealed class NtTypeFactoryImpl : NtTypeFactoryImplBase
        {
            public NtTypeFactoryImpl() : base(true)
            {
            }

            protected override sealed NtResult<NtMutant> OpenInternal(ObjectAttributes obj_attributes,
                MutantAccessRights desired_access, bool throw_on_error)
            {
                return NtMutant.Open(obj_attributes, desired_access, throw_on_error);
            }
        }
        #endregion

        #region Static Methods
        /// <summary>
        /// Create a new mutant
        /// </summary>
        /// <param name="path">The path to the mutant</param>
        /// <param name="root">The root object if path is relative</param>
        /// <param name="initial_owner">True to set current thread as initial owner</param>
        /// <returns>The opened mutant</returns>
        /// <exception cref="NtException">Thrown on error</exception>
        public static NtMutant Create(string path, NtObject root, bool initial_owner)
        {
            using (ObjectAttributes obja = new ObjectAttributes(path, AttributeFlags.CaseInsensitive, root))
            {
                return Create(obja, initial_owner, MutantAccessRights.MaximumAllowed);
            }
        }

        /// <summary>
        /// Create a new mutant
        /// </summary>
        /// <param name="object_attributes">Object attributes</param>
        /// <param name="initial_owner">True to set current thread as initial owner</param>
        /// <param name="desired_access">Desired access for mutant</param>
        /// <returns>The opened mutant</returns>
        /// <exception cref="NtException">Thrown on error</exception>
        public static NtMutant Create(ObjectAttributes object_attributes, bool initial_owner, MutantAccessRights desired_access)
        {
            NtSystemCalls.NtCreateMutant(out SafeKernelObjectHandle handle, desired_access, object_attributes, initial_owner).ToNtException();
            return new NtMutant(handle);
        }

        /// <summary>
        /// Create a new mutant
        /// </summary>
        /// <param name="object_attributes">Object attributes</param>
        /// <param name="initial_owner">True to set current thread as initial owner</param>
        /// <param name="desired_access">Desired access for mutant</param>
        /// <param name="throw_on_error">True to throw an exception on error.</param>
        /// <returns>The NT status code and object result.</returns>
        public static NtResult<NtMutant> Create(ObjectAttributes object_attributes, bool initial_owner, MutantAccessRights desired_access, bool throw_on_error)
        {
            return NtSystemCalls.NtCreateMutant(out SafeKernelObjectHandle handle, desired_access, object_attributes, initial_owner).CreateResult(throw_on_error, () => new NtMutant(handle));
        }

        /// <summary>
        /// Open a mutant
        /// </summary>
        /// <param name="path">The path to the mutant</param>
        /// <param name="root">The root object if path is relative</param>
        /// <param name="desired_access">Desired access for mutant</param>
        /// <returns>The opened mutant</returns>
        /// <exception cref="NtException">Thrown on error</exception>
        public static NtMutant Open(string path, NtObject root, MutantAccessRights desired_access)
        {
            using (ObjectAttributes obja = new ObjectAttributes(path, AttributeFlags.CaseInsensitive, root))
            {
                return Open(obja, desired_access);
            }
        }

        /// <summary>
        /// Open a mutant
        /// </summary>
        /// <param name="path">The path to the mutant</param>
        /// <param name="root">The root object if path is relative</param>
        /// <returns>The opened mutant</returns>
        /// <exception cref="NtException">Thrown on error</exception>
        public static NtMutant Open(string path, NtObject root)
        {
            return Open(path, root, MutantAccessRights.MaximumAllowed);
        }

        /// <summary>
        /// Open a mutant
        /// </summary>
        /// <param name="object_attributes">Object attributes</param>
        /// <param name="desired_access">Desired access for mutant</param>
        /// <returns>The opened mutant</returns>
        /// <exception cref="NtException">Thrown on error</exception>
        public static NtMutant Open(ObjectAttributes object_attributes, MutantAccessRights desired_access)
        {
            NtSystemCalls.NtOpenMutant(out SafeKernelObjectHandle handle, desired_access, object_attributes).ToNtException();
            return new NtMutant(handle);
        }

        /// <summary>
        /// Open a mutant
        /// </summary>
        /// <param name="object_attributes">Object attributes</param>
        /// <param name="desired_access">Desired access for mutant</param>
        /// <param name="throw_on_error">True to throw an exception on error.</param>
        /// <returns>The NT status code and object result.</returns>
        public static NtResult<NtMutant> Open(ObjectAttributes object_attributes, MutantAccessRights desired_access, bool throw_on_error)
        {
            return NtSystemCalls.NtOpenMutant(out SafeKernelObjectHandle handle, desired_access, object_attributes).CreateResult(throw_on_error, () => new NtMutant(handle));
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Release the mutant
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The previous release count</returns>
        public NtResult<int> Release(bool throw_on_error)
        {
            return NtSystemCalls.NtReleaseMutant(Handle, out int ret).CreateResult(throw_on_error, () => ret);
        }

        /// <summary>
        /// Release the mutant
        /// </summary>
        /// <returns>The previous release count</returns>
        public int Release()
        {
            return Release(true).Result;
        }

        /// <summary>
        /// Method to query information for this object type.
        /// </summary>
        /// <param name="info_class">The information class.</param>
        /// <param name="buffer">The buffer to return data in.</param>
        /// <param name="return_length">Return length from the query.</param>
        /// <returns>The NT status code for the query.</returns>
        public override NtStatus QueryInformation(MutantInformationClass info_class, SafeBuffer buffer, out int return_length)
        {
            return NtSystemCalls.NtQueryMutant(Handle, info_class, buffer, buffer.GetLength(), out return_length);
        }
        #endregion

        #region Public Properties

        /// <summary>
        /// Get the owner of the mutant.
        /// </summary>
        public ClientId Owner => new ClientId(Query<MutantOwnerInformation>(MutantInformationClass.MutantOwnerInformation).ClientId);
        /// <summary>
        /// Get current count.
        /// </summary>
        public int CurrentCount => Query<MutantBasicInformation>(MutantInformationClass.MutantBasicInformation).CurrentCount;
        /// <summary>
        /// Get wether mutant owned by current thread.
        /// </summary>
        public bool OwnedByCaller => Query<MutantBasicInformation>(MutantInformationClass.MutantBasicInformation).OwnedByCaller != 0;
        /// <summary>
        /// Get whether mutant is abandoned.
        /// </summary>
        public bool AbandonedState => Query<MutantBasicInformation>(MutantInformationClass.MutantBasicInformation).AbandonedState != 0;

        #endregion
    }
}
