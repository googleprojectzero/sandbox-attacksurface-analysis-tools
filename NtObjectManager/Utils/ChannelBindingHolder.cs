//  Copyright 2021 Google Inc. All Rights Reserved.
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

using NtCoreLib.Win32.Security.Authentication;
using System;
using System.Linq;

namespace NtObjectManager.Utils;

/// <summary>
/// Class to hold a channel binding value.
/// </summary>
public sealed class ChannelBindingHolder
{
    private readonly SecurityChannelBinding _value;

    /// <summary>
    /// Cast the holder to a SecurityChannelBinding
    /// </summary>
    /// <param name="holder">The holder.</param>
    public static explicit operator SecurityChannelBinding(ChannelBindingHolder holder) => holder?._value;

    /// <summary>
    /// Constructor.
    /// </summary>
    /// <param name="value">The channel binding application data.</param>
    public ChannelBindingHolder(SecurityChannelBinding value)
    {
        _value = value;
    }

    /// <summary>
    /// Constructor.
    /// </summary>
    /// <param name="value">The channel binding application data.</param>
    public ChannelBindingHolder(byte[] value)
    {
        _value = new SecurityChannelBinding(value);
    }

    /// <summary>
    /// Constructor.
    /// </summary>
    /// <param name="value">The channel binding application data.</param>
    public ChannelBindingHolder(object[] value) 
        : this(value.OfType<IConvertible>().Select(i => i.ToByte(null)).ToArray())
    {
    }
}
