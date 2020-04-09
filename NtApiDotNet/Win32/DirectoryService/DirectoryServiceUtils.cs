//  Copyright 2020 Google Inc. All Rights Reserved.
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
    /// Class implementing various utilities for directory services.
    /// </summary>
    public static class DirectoryServiceUtils
    {
        /// <summary>
        /// Get the generic mapping for directory services.
        /// </summary>
        /// <returns>The directory services generic mapping.</returns>
        public static GenericMapping GenericMapping
        {
            get
            {
                GenericMapping mapping = new GenericMapping
                {
                    GenericRead = DirectoryServiceAccessRights.ReadProp | DirectoryServiceAccessRights.List | DirectoryServiceAccessRights.ListObject,
                    GenericWrite = DirectoryServiceAccessRights.Self | DirectoryServiceAccessRights.WriteProp,
                    GenericExecute = DirectoryServiceAccessRights.List,
                    GenericAll = DirectoryServiceAccessRights.All
                };
                return mapping;
            }
        }

        /// <summary>
        /// Get a fake NtType for Directory Services.
        /// </summary>
        /// <returns>The fake Directory Services NtType</returns>
        public static NtType NtType => new NtType("DirectoryService", GenericMapping,
                        typeof(DirectoryServiceAccessRights), typeof(DirectoryServiceAccessRights),
                        MandatoryLabelPolicy.NoWriteUp);
    }
}
