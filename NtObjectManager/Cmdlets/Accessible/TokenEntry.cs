//  Copyright 2017 Google Inc. All Rights Reserved.
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
using NtCoreLib.Security.Token;
using System;

namespace NtObjectManager.Cmdlets.Accessible;

internal struct TokenEntry : IDisposable
{
    public readonly NtToken Token;
    public readonly TokenInformation Information;

    private static NtToken DuplicateToken(NtToken token)
    {
        if (token.TokenType == TokenType.Primary)
        {
            return token.DuplicateToken(TokenType.Impersonation, SecurityImpersonationLevel.Impersonation,
                TokenAccessRights.Query | TokenAccessRights.Impersonate | TokenAccessRights.Duplicate);
        }
        else
        {
            return token.Duplicate(TokenAccessRights.Query | TokenAccessRights.Impersonate | TokenAccessRights.Duplicate);
        }
    }

    public TokenEntry(NtToken token) 
        : this(token, null)
    {
    }

    public TokenEntry(NtToken token, NtProcess process) 
        : this(token, token, process)
    {
    }

    public TokenEntry(NtToken token, NtToken imp_token, NtProcess process)
    {
        Information = process == null ? new TokenInformation(token, null) : new ProcessTokenInformation(token, process);
        Token = DuplicateToken(imp_token);
    }

    public void Dispose()
    {
        Token?.Dispose();
    }
}