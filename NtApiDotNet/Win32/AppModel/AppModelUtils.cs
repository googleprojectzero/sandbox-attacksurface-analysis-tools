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

using System.Collections.Generic;
using System.Linq;

namespace NtApiDotNet.Win32.AppModel
{
    /// <summary>
    /// Utilities for AppModel applications.
    /// </summary>
    public static class AppModelUtils
    {
        private static IEnumerable<Sid> ParseSidsAndAttributes(int count, SafeProcessHeapBuffer sids)
        {
            using (sids)
            {
                sids.Initialize<SidAndAttributes>((uint)count);
                SidAndAttributes[] arr = sids.ReadArray<SidAndAttributes>(0, count);
                try
                {
                    return arr.Select(s => new Sid(s.Sid)).ToArray();
                }
                finally
                {
                    NtHeap heap = NtHeap.Current;
                    foreach (var ent in arr)
                    {
                        heap.Free(HeapAllocFlags.None, ent.Sid.ToInt64());
                    }
                }
            }
        }

        private static NtStatus SetLoopbackException(Sid package_sid, bool remove, bool throw_on_error)
        {
            var result = GetLoopbackException(throw_on_error);
            if (!result.IsSuccess)
            {
                return result.Status;
            }

            List<Sid> sids = result.Result.ToList();
            if (remove)
            {
                sids.RemoveAll(s => s == package_sid);
            }
            else
            {
                sids.Add(package_sid);
            }

            using (var list = new DisposableList())
            {
                return AppModelNativeMethods.NetworkIsolationSetAppContainerConfig(sids.Count, 
                    list.CreateSidAndAttributes(sids)).ToNtException(throw_on_error);
            }
        }

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

        /// <summary>
        /// Get the list of package SIDs with a loopback exception.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The list of package SIDs with a loopback exception.</returns>
        public static NtResult<IEnumerable<Sid>> GetLoopbackException(bool throw_on_error)
        {
            return AppModelNativeMethods.NetworkIsolationGetAppContainerConfig(out int count, out SafeProcessHeapBuffer sids)
                .CreateWin32Result(throw_on_error, () => ParseSidsAndAttributes(count, sids));
        }

        /// <summary>
        /// Get the list of package SIDs with a loopback exception.
        /// </summary>
        /// <returns>The list of package SIDs with a loopback exception.</returns>
        public static IEnumerable<Sid> GetLoopbackException()
        {
            return GetLoopbackException(true).Result;
        }

        /// <summary>
        /// Add a loopback exception to the list.
        /// </summary>
        /// <param name="package_sid">The package SID to add.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public static NtStatus AddLoopbackException(Sid package_sid, bool throw_on_error)
        {
            return SetLoopbackException(package_sid, false, throw_on_error);
        }

        /// <summary>
        /// Add a loopback exception to the list.
        /// </summary>
        /// <param name="package_sid">The package SID to add.</param>
        public static void AddLoopbackException(Sid package_sid)
        {
            AddLoopbackException(package_sid, true);
        }

        /// <summary>
        /// Remove a loopback exception from the list.
        /// </summary>
        /// <param name="package_sid">The package SID to remove.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public static NtStatus RemoveLoopbackException(Sid package_sid, bool throw_on_error)
        {
            return SetLoopbackException(package_sid, true, throw_on_error);
        }

        /// <summary>
        /// Remove a loopback exception to the list.
        /// </summary>
        /// <param name="package_sid">The package SID to remove.</param>
        public static void RemoveLoopbackException(Sid package_sid)
        {
            RemoveLoopbackException(package_sid, true);
        }
    }
}
