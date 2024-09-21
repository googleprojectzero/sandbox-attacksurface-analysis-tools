﻿//  Copyright 2016, 2017 Google Inc. All Rights Reserved.
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

#nullable enable

using NtCoreLib.Security.Authorization;
using System.Collections.Generic;

namespace NtCoreLib.Win32.Service.Interop;

internal class ServiceFakeTypeFactory : NtFakeTypeFactory
{
    public override IEnumerable<NtType> CreateTypes()
    {
        return new NtType[] {
            new NtType(ServiceUtils.SERVICE_NT_TYPE_NAME, ServiceUtils.GetServiceGenericMapping(),
                    typeof(ServiceAccessRights), typeof(ServiceAccessRights),
                    MandatoryLabelPolicy.NoWriteUp),
            new NtType(ServiceUtils.SCM_NT_TYPE_NAME, ServiceUtils.GetScmGenericMapping(),
                    typeof(ServiceControlManagerAccessRights), typeof(ServiceControlManagerAccessRights),
                    MandatoryLabelPolicy.NoWriteUp)
        };
    }
}
