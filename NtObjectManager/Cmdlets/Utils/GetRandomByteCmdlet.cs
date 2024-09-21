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

using System;
using System.Management.Automation;

namespace NtObjectManager.Cmdlets.Utils;

/// <summary>
/// <para type="synopsis">Get a random byte array.</para>
/// <para type="description">This cmdlet returns a byte array containing random bytes up to a fixed size.</para>
/// </summary>
/// <example>
///   <code>$ba = Get-RandomByte -Size 100</code>
///   <para>Get a random byte array of length 100.</para>
/// </example>
[Cmdlet(VerbsCommon.Get, "RandomByte")]
[OutputType(typeof(byte[]))]
public class GetRandomByteCmdlet : Cmdlet
{
    private static readonly Random _random = new();

    /// <summary>
    /// <para type="description">The size of the random byte array.</para>
    /// </summary>
    [Parameter(Position = 0, Mandatory = true)]
    public int Size { get; set; }

    /// <summary>
    /// Overridden ProcessRecord.
    /// </summary>
    protected override void ProcessRecord()
    {
        byte[] ret = new byte[Size];
        _random.NextBytes(ret);
        WriteObject(ret, false);
    }
}
