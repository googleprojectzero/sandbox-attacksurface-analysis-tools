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

using System.Collections.Generic;

namespace NtApiDotNet.Win32.Security.Policy
{
    internal class LsaFakeTypeFactory : NtFakeTypeFactory
    {
        public override IEnumerable<NtType> CreateTypes()
        {
            return new NtType[] {
                new NtType(LsaPolicyUtils.LSA_POLICY_NT_TYPE_NAME, LsaPolicyUtils.GetLsaPolicyGenericMapping(),
                        typeof(LsaPolicyAccessRights), typeof(LsaPolicyAccessRights),
                        MandatoryLabelPolicy.NoWriteUp),
                new NtType(LsaPolicyUtils.LSA_SECRET_NT_TYPE_NAME, LsaPolicyUtils.GetLsaSecretGenericMapping(),
                        typeof(LsaSecretAccessRights), typeof(LsaSecretAccessRights),
                        MandatoryLabelPolicy.NoWriteUp),
                new NtType(LsaPolicyUtils.LSA_ACCOUNT_NT_TYPE_NAME, LsaPolicyUtils.GetLsaAccountGenericMapping(),
                        typeof(LsaAccountAccessRights), typeof(LsaAccountAccessRights),
                        MandatoryLabelPolicy.NoWriteUp),
                new NtType(LsaPolicyUtils.LSA_TRUSTED_DOMAIN_NT_TYPE_NAME, LsaPolicyUtils.GetLsaTrustedDomainGenericMapping(),
                        typeof(LsaTrustedDomainAccessRights), typeof(LsaTrustedDomainAccessRights),
                        MandatoryLabelPolicy.NoWriteUp)
            };
        }
    }
}
