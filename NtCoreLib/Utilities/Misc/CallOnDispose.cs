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

using System;

namespace NtApiDotNet.Utilities.Misc
{
    /// <summary>
    /// Class which calls a delegate on dispose.
    /// </summary>
    public sealed class CallOnDispose : IDisposable
    {
        private readonly Action _action;
        private bool _disposed;

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="action">The delegate to call on dispose.</param>
        public CallOnDispose(Action action)
        {
            _action = action;
        }

        /// <summary>
        /// Dispose and call the action.
        /// </summary>
        public void Dispose()
        {
            try
            {
                if (!_disposed)
                {
                    _disposed = true;
                }
                _action();
            }
            catch
            {
            }
        }
    }
}
