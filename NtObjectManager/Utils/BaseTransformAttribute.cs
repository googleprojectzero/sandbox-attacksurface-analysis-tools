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

using NtCoreLib;
using System;
using System.Management.Automation;

namespace NtObjectManager.Utils;

abstract class BaseTransformAttribute : ArgumentTransformationAttribute
{
    protected abstract NtResult<object> Parse(string value, bool throw_on_error);
    protected abstract object DefaultValue(object obj);
    private readonly Type _type;

    protected BaseTransformAttribute(Type type)
    {
        _type = type;
    }

    public override object Transform(EngineIntrinsics engineIntrinsics, object inputData)
    {
        if (inputData is string var_name && var_name.StartsWith("$"))
        {
            // Work around a weird bug, if this starts with a $ it's probably a variable.
            // Query for it from the session state.
            inputData = engineIntrinsics.SessionState.PSVariable.GetValue(var_name.Substring(1));
        }

        if (inputData is string s)
        {
            var result = Parse(s, false);
            if (result.IsSuccess)
            {
                return result.Result;
            }
        }

        if (inputData is PSObject obj && obj.BaseObject != null)
        {
            if (_type == obj.BaseObject.GetType())
            {
                return obj.BaseObject;
            }
        }

        return DefaultValue(inputData);
    }
}
