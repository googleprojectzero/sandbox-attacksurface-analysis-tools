//  Copyright 2022 Google LLC. All Rights Reserved.
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

using System;

namespace NtApiDotNet.Win32.Security.Authentication.NegoEx
{
    /// <summary>
    /// Known authentication schemes for NEGOEX.
    /// </summary>
    public static class NegoExAuthSchemes
    {
        /// <summary>
        /// PKU2U.
        /// </summary>
        public static readonly Guid PKU2U = new Guid("0d53335c-f9ea-4d0d-b2ec-4ae3786ec308");

        /// <summary>
        /// The the name of a authentication scheme from it's GUID.
        /// </summary>
        /// <param name="guid">The authentication scheme GUID.</param>
        /// <returns>The name, or an empty string is not known.</returns>
        public static string GetName(Guid guid)
        {
            if (guid == PKU2U)
                return "PKU2U";
            return string.Empty;
        }
    }
}
