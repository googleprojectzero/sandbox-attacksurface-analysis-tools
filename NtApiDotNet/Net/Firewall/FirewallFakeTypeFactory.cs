//  Copyright 2021 Google LLC. All Rights Reserved.
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

using System.Collections.Generic;

namespace NtApiDotNet.Net.Firewall
{
    internal class FirewallFakeTypeFactory : NtFakeTypeFactory
    {
        public override IEnumerable<NtType> CreateTypes()
        {
            return new NtType[] {
                new NtType(FirewallUtils.FIREWALL_NT_TYPE_NAME, FirewallUtils.GetGenericMapping(),
                        typeof(FirewallAccessRights), typeof(FirewallAccessRights),
                        MandatoryLabelPolicy.NoWriteUp),
                new NtType(FirewallUtils.FIREWALL_FILTER_NT_TYPE_NAME, FirewallUtils.GetFilterGenericMapping(),
                        typeof(FirewallFilterAccessRights), typeof(FirewallFilterAccessRights),
                        MandatoryLabelPolicy.NoWriteUp)
            };
        }
    }
}
