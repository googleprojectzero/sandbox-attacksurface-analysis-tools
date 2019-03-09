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
    /// Class to represent a NT Semaphore object.
    /// </summary>
    [NtType("Semaphore")]
    public class NtSemaphore : NtObjectWithDuplicateAndInfo<NtSemaphore, SemaphoreAccessRights, SemaphoreInformationClass, SemaphoreInformationClass>
    {
        #region Constructors
        internal NtSemaphore(SafeKernelObjectHandle handle) : base(handle)
        {
        }

        internal sealed class NtTypeFactoryImpl : NtTypeFactoryImplBase
        {
            public NtTypeFactoryImpl() : base(true)
            {
            }

            protected override sealed NtResult<NtSemaphore> OpenInternal(ObjectAttributes obj_attributes,
                SemaphoreAccessRights desired_access, bool throw_on_error)
            {
                return NtSemaphore.Open(obj_attributes, desired_access, throw_on_error);
            }
        }

        #endregion

        #region Static Methods
        /// <summary>
        /// Create a semaphore object.
        /// </summary>
        /// <param name="object_attributes">The object attributes for the object</param>
        /// <param name="desired_access">The desired access for the object</param>
        /// <param name="initial_count">Initial count for semaphore</param>
        /// <param name="maximum_count">Maximum count for semaphore</param>
        /// <param name="throw_on_error">True to throw an exception on error.</param>
        /// <returns>The NT status code and object result.</returns>
        public static NtResult<NtSemaphore> Create(ObjectAttributes object_attributes, SemaphoreAccessRights desired_access, int initial_count, int maximum_count, bool throw_on_error)
        {
            return NtSystemCalls.NtCreateSemaphore(out SafeKernelObjectHandle handle, desired_access, object_attributes, initial_count, maximum_count).CreateResult(throw_on_error, () => new NtSemaphore(handle));
        }

        /// <summary>
        /// Create a semaphore object.
        /// </summary>
        /// <param name="object_attributes">The object attributes for the object</param>
        /// <param name="desired_access">The desired access for the object</param>
        /// <param name="initial_count">Initial count for semaphore</param>
        /// <param name="maximum_count">Maximum count for semaphore</param>
        /// <returns>The opened object</returns>
        public static NtSemaphore Create(ObjectAttributes object_attributes, SemaphoreAccessRights desired_access, int initial_count, int maximum_count)
        {
            return Create(object_attributes, desired_access, initial_count, maximum_count, true).Result;
        }

        /// <summary>
        /// Create a semaphore object.
        /// </summary>
        /// <param name="path">The path to the object</param>
        /// <param name="root">The root if path is relative</param>
        /// <param name="initial_count">Initial count for semaphore</param>
        /// /// <param name="maximum_count">Maximum count for semaphore</param>
        /// <returns>The opened object</returns>
        public static NtSemaphore Create(string path, NtObject root, int initial_count, int maximum_count)
        {
            using (ObjectAttributes obja = new ObjectAttributes(path, AttributeFlags.CaseInsensitive, root))
            {
                return Create(obja, SemaphoreAccessRights.MaximumAllowed, initial_count, maximum_count);
            }
        }

        /// <summary>
        /// Open a semaphore object.
        /// </summary>
        /// <param name="object_attributes">The object attributes for the object</param>
        /// <param name="desired_access">The desired access for the object</param>
        /// <param name="throw_on_error">True to throw an exception on error.</param>
        /// <returns>The NT status code and object result.</returns>
        public static NtResult<NtSemaphore> Open(ObjectAttributes object_attributes, SemaphoreAccessRights desired_access, bool throw_on_error)
        {
            return NtSystemCalls.NtOpenSemaphore(out SafeKernelObjectHandle handle, desired_access, object_attributes).CreateResult(throw_on_error, () => new NtSemaphore(handle));
        }

        /// <summary>
        /// Open a semaphore object.
        /// </summary>
        /// <param name="object_attributes">The object attributes for the object</param>
        /// <param name="desired_access">The desired access for the object</param>
        /// <returns>The opened object</returns>
        public static NtSemaphore Open(ObjectAttributes object_attributes, SemaphoreAccessRights desired_access)
        {
            return Open(object_attributes, desired_access, true).Result;
        }

        /// <summary>
        /// Open a semaphore object.
        /// </summary>
        /// <param name="path">The path to the object</param>
        /// <param name="root">The root if path is relative</param>
        /// <param name="desired_access">The desired access for the object</param>
        /// <returns>The opened object</returns>
        public static NtSemaphore Open(string path, NtObject root, SemaphoreAccessRights desired_access)
        {
            using (ObjectAttributes obja = new ObjectAttributes(path, AttributeFlags.CaseInsensitive, root))
            {
                return Open(obja, desired_access);
            }
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Release the semaphore
        /// </summary>
        /// <param name="count">The release count</param>
        /// <returns>The previous count</returns>
        public int Release(int count)
        {
            return Release(count, true).Result;
        }

        /// <summary>
        /// Release the semaphore
        /// </summary>
        /// <param name="count">The release count</param>
        /// <param name="throw_on_error">True to throw an exception on error.</param>
        /// <returns>The previous count</returns>
        public NtResult<int> Release(int count, bool throw_on_error)
        {
            return NtSystemCalls.NtReleaseSemaphore(Handle, count, out int previous_count).CreateResult(throw_on_error, () => previous_count);
        }

        /// <summary>
        /// Method to query information for this object type.
        /// </summary>
        /// <param name="info_class">The information class.</param>
        /// <param name="buffer">The buffer to return data in.</param>
        /// <param name="return_length">Return length from the query.</param>
        /// <returns>The NT status code for the query.</returns>
        public override NtStatus QueryInformation(SemaphoreInformationClass info_class, SafeBuffer buffer, out int return_length)
        {
            return NtSystemCalls.NtQuerySemaphore(Handle, info_class, buffer, (int)buffer.ByteLength, out return_length);
        }
        #endregion

        #region Public Properties

        /// <summary>
        /// Current count of the semaphore.
        /// </summary>
        public int CurrentCount => Query<SemaphoreBasicInformation>(SemaphoreInformationClass.SemaphoreBasicInformation).CurrentCount;

        /// <summary>
        /// Maximum count of the semaphore.
        /// </summary>
        public int MaximumCount => Query<SemaphoreBasicInformation>(SemaphoreInformationClass.SemaphoreBasicInformation).MaximumCount;
        #endregion
    }
}
