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

namespace NtApiDotNet.Win32.AppModel
{
    /// <summary>
    /// Utilities for AppModel applications.
    /// </summary>
    public static class AppModelUtils
    {
        /// <summary>
        /// Activate an application from its Application Model ID.
        /// </summary>
        /// <param name="app_model_id">The app model ID.</param>
        /// <param name="arguments">Arguments for the activation.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The PID of the process.</returns>
        public static NtResult<int> ActivateApplication(string app_model_id, string arguments, bool throw_on_error)
        {
            IApplicationActivationManager mgr = (IApplicationActivationManager)new ApplicationActivationManager();
            return mgr.ActivateApplication(app_model_id, arguments, ACTIVATEOPTIONS.AO_NONE, out int pid).CreateResult(throw_on_error, () => pid);
        }

        /// <summary>
        /// Activate an application from its Application Model ID.
        /// </summary>
        /// <param name="app_model_id">The app model ID.</param>
        /// <param name="arguments">Arguments for the activation.</param>
        /// <returns>The PID of the process.</returns>
        public static int ActivateApplication(string app_model_id, string arguments)
        {
            return ActivateApplication(app_model_id, arguments, true).Result;
        }
    }
}
