//  Copyright 2021 Google LLC. All Rights Reserved.
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

namespace NtApiDotNet.Win32.DirectoryService
{
    /// <summary>
    /// Structure to represent a directory service name.
    /// </summary>
    public struct DirectoryServiceNameResult
    {
        /// <summary>
        /// Status of the name.
        /// </summary>
        public DirectoryServiceNameError Status { get; }
        /// <summary>
        /// Domain of the name.
        /// </summary>
        public string Domain { get; }
        /// <summary>
        /// Name of the name.
        /// </summary>
        public string Name { get; }

        private DirectoryServiceNameResult(DS_NAME_RESULT_ITEMW item)
        {
            Status = item.status;
            Domain = item.pDomain;
            Name = item.pName;
        }

        internal static DirectoryServiceNameResult Create(DS_NAME_RESULT_ITEMW item)
        {
            return new DirectoryServiceNameResult(item);
        }
    }
}
