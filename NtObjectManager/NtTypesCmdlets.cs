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
using System;
using System.Management.Automation;

namespace NtObjectManager
{
    /// <summary>
    /// <para type="synopsis">Get NT type information.</para>
    /// <para type="description">This cmdlet gets NT type information from the operating system. If run without parameters it'll retrieve all types. 
    /// You can limit it to only one type using the -TypeName parameter.</para>
    /// </summary>
    /// <example>
    ///   <code>Get-NtType</code>
    ///   <para>Get all NT types.</para>
    /// </example>
    /// <example>
    ///   <code>Get-NtType | Where-Object SecurityRequired -eq $False</code>
    ///   <para>Get all NT types which don't require security.</para>
    /// </example>
    /// <example>
    ///   <code>Get-NtType Directory</code>
    ///   <para>Get the Directory NT type.</para>
    /// </example>
    [Cmdlet(VerbsCommon.Get, "NtType")]
    [OutputType(typeof(NtType))]
    public sealed class GetNtTypesCmdlet : Cmdlet
    {
        /// <summary>
        /// <para type="description">Specify a specific NT type to retrieve.</para>
        /// </summary>
        [Parameter(Position = 0)]
        public string TypeName { get; set; }

        /// <summary>
        /// Overridden ProcessRecord method.
        /// </summary>
        protected override void ProcessRecord()
        {
            if (!string.IsNullOrWhiteSpace(TypeName))
            {
                NtType type_info = NtType.GetTypeByName(TypeName);
                if (type_info != null)
                {
                    WriteObject(type_info);
                }
                else
                {
                    throw new ArgumentException(String.Format("Invalid Type Name {0}", TypeName));
                }
            }
            else
            {
                WriteObject(NtType.GetTypes(), true);
            }
        }
    }
}
