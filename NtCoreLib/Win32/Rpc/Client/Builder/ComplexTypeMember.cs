//  Copyright 2019 Google Inc. All Rights Reserved.
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

using NtCoreLib.Ndr.Dce;
using System;
using System.CodeDom;

namespace NtCoreLib.Win32.Rpc.Client.Builder;

[Serializable]
internal sealed class ComplexTypeMember
{
    public NdrBaseTypeReference MemberType { get; }
    public int Offset { get; }
    public string Name { get; }
    public CodeExpression Selector { get; }
    public bool Default { get; }
    public bool Hidden { get; }

    internal ComplexTypeMember(NdrBaseTypeReference member_type, int offset, string name, CodeExpression selector, bool default_arm, bool hidden)
    {
        MemberType = member_type;
        Offset = offset;
        Name = name;
        Selector = selector;
        Default = default_arm;
        Hidden = hidden;
    }
}
