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
using NtCoreLib.Security.Authorization;

namespace NtObjectManager.Utils;

class SidTransformAttribute : BaseTransformAttribute
{
    public SidTransformAttribute() 
        : base(typeof(Sid))
    {
    }

    protected override object DefaultValue(object obj)
    {
        if (obj is Sid sid)
        {
            return sid;
        }
        return new Sid(SecurityAuthority.Null, 0);
    }

    protected override NtResult<object> Parse(string value, bool throw_on_error)
    {
        return Sid.Parse(value, false).Cast<object>();
    }
}
