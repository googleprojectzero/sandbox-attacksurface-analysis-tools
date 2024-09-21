//  Copyright 2023 Google LLC. All Rights Reserved.
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
using NtCoreLib.Win32.SideBySide.Interop;

namespace NtCoreLib.Win32.SideBySide
{
    /// <summary>
    /// Scoped activated activation context.
    /// </summary>
    /// <remarks>Dispose of the object to deactivate the activation context.</remarks>
    public sealed class ScopedActivationContext : IDisposable
    {
        #region Private Members
        private readonly IntPtr _cookie;
        #endregion

        #region Internal Members
        internal ScopedActivationContext(IntPtr cookie)
        {
            _cookie = cookie;
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Deactivate the activation context.
        /// </summary>
        /// <param name="force"></param>
        public void Deactivate(bool force = false)
        {
            NativeMethods.DeactivateActCtx(force ? DeactivateActCtxFlags.DEACTIVATE_ACTCTX_FLAG_FORCE_EARLY_DEACTIVATION : 0, 
                _cookie).ToNtException(true);
        }

        /// <summary>
        /// Dispose method.
        /// </summary>
        public void Dispose()
        {
            try
            {
                Deactivate();
            }
            catch (NtException)
            {
            }
        }
        #endregion
    }
}
