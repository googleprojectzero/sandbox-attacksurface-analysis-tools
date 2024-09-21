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

using System.CodeDom;

namespace NtCoreLib.Win32.Rpc.Client.Builder;

internal sealed class AdditionalArguments
{
    public CodeExpression[] FixedArgs { get; }
    public CodeTypeReference[] Params { get; }
    public bool Generic { get; }
    public CodeTypeReference GenericType { get; set; }

    public AdditionalArguments(CodeExpression[] args, CodeTypeReference[] ps, bool generic)
    {
        FixedArgs = args ?? new CodeExpression[0];
        Params = ps ?? new CodeTypeReference[0];
        Generic = generic;
    }

    public AdditionalArguments(bool generic, params CodeExpression[] args) : this(args, null, generic)
    {
    }

    public AdditionalArguments(bool generic, params CodeTypeReference[] ps) : this(null, ps, generic)
    {
    }

    public AdditionalArguments(bool generic)
        : this(null, null, generic)
    {
    }

    public AdditionalArguments(CodeTypeReference generic_type)
        : this(true)
    {
        GenericType = generic_type;
    }

    public AdditionalArguments() : this(null, null, false)
    {
    }
}
