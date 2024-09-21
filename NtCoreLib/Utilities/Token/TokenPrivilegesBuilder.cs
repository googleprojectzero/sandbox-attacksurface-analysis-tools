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

#nullable enable

using System.Collections.Generic;
using System.Linq;
using NtCoreLib.Native.SafeBuffers;
using NtCoreLib.Security.Token;

namespace NtCoreLib.Utilities.Token;

internal class TokenPrivilegesBuilder
{
    private readonly List<LuidAndAttributes> _privs;

    public TokenPrivilegesBuilder() => _privs = new List<LuidAndAttributes>();

    public void AddPrivilege(Luid luid, PrivilegeAttributes attributes)
    {
        LuidAndAttributes priv = new()
        {
            Luid = luid,
            Attributes = attributes
        };
        _privs.Add(priv);
    }

    public void AddPrivilege(TokenPrivilegeValue name, PrivilegeAttributes attributes)
    {
        Luid luid = new((uint)name, 0);
        AddPrivilege(luid, attributes);
    }

    public void AddPrivilege(string name, bool enable)
    {
        AddPrivilege(new TokenPrivilege(name, enable ? PrivilegeAttributes.Enabled : PrivilegeAttributes.Disabled));
    }

    public void AddPrivilege(TokenPrivilege privilege)
    {
        AddPrivilege(privilege.Luid, privilege.Attributes);
    }

    public void AddPrivilegeRange(IEnumerable<TokenPrivilege> privileges)
    {
        _privs.AddRange(privileges.Select(p => new LuidAndAttributes() { Luid = p.Luid, Attributes = p.Attributes }));
    }

    public SafeTokenPrivilegesBuffer ToBuffer()
    {
        return new SafeTokenPrivilegesBuffer(_privs.ToArray());
    }
}

