//  Copyright 2018 Google Inc. All Rights Reserved.
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
    /// Class representing a NT Partition object
    /// </summary>
    [NtType("Partition")]
    public class NtPartition : NtObjectWithDuplicate<NtPartition, MemoryPartitionAccessRights>
    {
        #region Constructors
        internal NtPartition(SafeKernelObjectHandle handle) : base(handle)
        {
        }

        internal sealed class NtTypeFactoryImpl : NtTypeFactoryImplBase
        {
            public NtTypeFactoryImpl() : base(true)
            {
            }

            protected override sealed NtResult<NtPartition> OpenInternal(ObjectAttributes obj_attributes,
                MemoryPartitionAccessRights desired_access, bool throw_on_error)
            {
                return NtPartition.Open(obj_attributes, desired_access, throw_on_error);
            }
        }
        #endregion

        #region Static Methods

        /// <summary>
        /// Create a partition object
        /// </summary>
        /// <param name="object_attributes">The object attributes</param>
        /// <param name="parent_partition">Optional parent parition.</param>
        /// <param name="desired_access">Desired access for the partition.</param>
        /// <param name="preferred_node">The preferred node, -1 for any node.</param>
        /// <param name="throw_on_error">True to throw an exception on error.</param>
        /// <returns>The NT status code and object result.</returns>
        public static NtResult<NtPartition> Create(ObjectAttributes object_attributes, MemoryPartitionAccessRights desired_access, NtPartition parent_partition, int preferred_node, bool throw_on_error)
        {
            return NtSystemCalls.NtCreatePartition(parent_partition.GetHandle(),
                out SafeKernelObjectHandle handle, desired_access, object_attributes, preferred_node).CreateResult(throw_on_error, () => new NtPartition(handle));
        }

        /// <summary>
        /// Create a partition object
        /// </summary>
        /// <param name="object_attributes">The object attributes</param>
        /// <param name="parent_partition">Optional parent parition.</param>
        /// <param name="desired_access">Desired access for the partition.</param>
        /// <param name="preferred_node">The preferred node, -1 for any node.</param>
        /// <returns>The NT status code and object result.</returns>
        public static NtPartition Create(ObjectAttributes object_attributes, MemoryPartitionAccessRights desired_access, NtPartition parent_partition, int preferred_node)
        {
            return Create(object_attributes, desired_access, parent_partition, preferred_node, true).Result;
        }

        /// <summary>
        /// Open a partition object
        /// </summary>
        /// <param name="object_attributes">The object attributes</param>
        /// <param name="desired_access">Desired access for the partition.</param>
        /// <param name="throw_on_error">True to throw an exception on error.</param>
        /// <returns>The NT status code and object result.</returns>
        public static NtResult<NtPartition> Open(ObjectAttributes object_attributes, MemoryPartitionAccessRights desired_access, bool throw_on_error)
        {
            return NtSystemCalls.NtOpenPartition(out SafeKernelObjectHandle handle, desired_access, object_attributes).CreateResult(throw_on_error, () => new NtPartition(handle));
        }

        /// <summary>
        /// Open a partition object
        /// </summary>
        /// <param name="object_attributes">The object attributes</param>
        /// <param name="desired_access">Desired access for the partition.</param>
        /// <returns>The NT status code and object result.</returns>
        public static NtPartition Open(ObjectAttributes object_attributes, MemoryPartitionAccessRights desired_access)
        {
            return Open(object_attributes, desired_access, true).Result;
        }

        #endregion
    }
}