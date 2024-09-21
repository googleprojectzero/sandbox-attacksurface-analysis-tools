//  Copyright 2016 Google Inc. All Rights Reserved.
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

using System;

namespace NtCoreLib.Utilities.Token;

/// <summary>
/// Disposable class to scope an impersonation context.
/// </summary>
public sealed class ThreadImpersonationContext : IDisposable
{
    private readonly NtThread _thread;
    private readonly bool _container;

    internal ThreadImpersonationContext(bool container)
    {
        _container = container;
    }

    internal ThreadImpersonationContext(NtThread thread)
        : this(false)
    {
        _thread = thread;
    }

    internal ThreadImpersonationContext()
        : this(NtThread.Current.Duplicate())
    {
    }

    /// <summary>
    /// Revert impersonation back to the current user.
    /// </summary>
    public void Revert()
    {
        if (_container)
        {
            NtThread.DetachContainer(false);
        }
        else if (!_thread.Handle.IsClosed)
        {
            using (_thread)
            {
                _thread.SetImpersonationToken(null, false);
            }
        }
    }

    void IDisposable.Dispose()
    {
        Revert();
    }
}
