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

using NtCoreLib;
using System.Management.Automation;

namespace NtObjectManager.Cmdlets.Object;

/// <summary>
/// <para type="synopsis">Create a new NT key object.</para>
/// <para type="description">This cmdlet creates a new NT key object. The absolute path to the object in the NT object manager name space must be specified. 
/// It's also possible to create the object relative to an existing object by specified the -Root parameter.</para>
/// </summary>
/// <example>
///   <code>$obj = New-NtKey \Registry\Machine\Software\ABC</code>
///   <para>Create a new key object with an absolute path.</para>
/// </example>
/// <example>
///   <code>$obj = New-NtKey -Path \Registry\Machine\Software\ABC&#x0A;$obj.SetValue("ValueName", String, "DataValue")</code>
///   <para>Create a new event object and set a string value.</para>
/// </example>
/// <para type="link">about_ManagingNtObjectLifetime</para>
[Cmdlet(VerbsCommon.New, "NtKey")]
[OutputType(typeof(NtKey))]
public sealed class NewNtKeyCmdlet : GetNtKeyCmdlet
{
    /// <summary>
    /// Method to create an object from a set of object attributes.
    /// </summary>
    /// <param name="obj_attributes">The object attributes to create/open from.</param>
    /// <returns>The newly created object.</returns>
    protected override object CreateObject(ObjectAttributes obj_attributes)
    {
        return NtKey.Create(obj_attributes, Access, Options, Transaction);
    }
}
