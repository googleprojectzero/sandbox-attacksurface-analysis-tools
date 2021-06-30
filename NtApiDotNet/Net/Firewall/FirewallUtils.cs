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

using NtApiDotNet.Win32;
using System;
using System.Runtime.InteropServices;
using System.Text;

namespace NtApiDotNet.Net.Firewall
{
    /// <summary>
    /// Static class for firewall utility functions.
    /// </summary>
    public static class FirewallUtils
    {
        #region Public Members
        /// <summary>
        /// Name for fake NT type.
        /// </summary>
        public const string FIREWALL_NT_TYPE_NAME = "Firewall";

        /// <summary>
        /// Name for fake filter NT type.
        /// </summary>
        public const string FIREWALL_FILTER_NT_TYPE_NAME = "FirewallFilter";

        /// <summary>
        /// Get the NT type for the firewall.
        /// </summary>
        public static NtType FirewallType => NtType.GetTypeByName(FIREWALL_NT_TYPE_NAME);

        /// <summary>
        /// Get the NT type for the firewall.
        /// </summary>
        public static NtType FirewallFilterType => NtType.GetTypeByName(FIREWALL_FILTER_NT_TYPE_NAME);

        /// <summary>
        /// Get the generic mapping for a firewall object.
        /// </summary>
        /// <returns>The firewall object generic mapping.</returns>
        public static GenericMapping GetGenericMapping()
        {
            return new GenericMapping()
            {
                GenericRead = FirewallAccessRights.ReadControl | FirewallAccessRights.BeginReadTxn |
                        FirewallAccessRights.Classify | FirewallAccessRights.Open |
                        FirewallAccessRights.Read | FirewallAccessRights.ReadStats,
                GenericExecute = FirewallAccessRights.ReadControl | FirewallAccessRights.Enum |
                        FirewallAccessRights.Subscribe,
                GenericWrite = FirewallAccessRights.ReadControl | FirewallAccessRights.Add |
                        FirewallAccessRights.AddLink | FirewallAccessRights.BeginWriteTxn |
                        FirewallAccessRights.Write,
                GenericAll = FirewallAccessRights.Delete | FirewallAccessRights.WriteDac |
                        FirewallAccessRights.WriteOwner | FirewallAccessRights.ReadControl |
                        FirewallAccessRights.BeginReadTxn | FirewallAccessRights.Classify |
                        FirewallAccessRights.Open | FirewallAccessRights.Read |
                        FirewallAccessRights.ReadStats | FirewallAccessRights.Enum |
                        FirewallAccessRights.Subscribe | FirewallAccessRights.Add |
                        FirewallAccessRights.AddLink | FirewallAccessRights.BeginWriteTxn |
                        FirewallAccessRights.Write
            };
        }

        /// <summary>
        /// Get the generic mapping for a firewall filter object.
        /// </summary>
        /// <returns>The firewall filter object generic mapping.</returns>
        public static GenericMapping GetFilterGenericMapping()
        {
            return new GenericMapping()
            {
                GenericRead = FirewallFilterAccessRights.ReadControl,
                GenericExecute = FirewallFilterAccessRights.ReadControl | FirewallFilterAccessRights.Match,
                GenericWrite = FirewallFilterAccessRights.ReadControl,
                GenericAll = FirewallFilterAccessRights.ReadControl | FirewallFilterAccessRights.Match
            };
        }

        /// <summary>
        /// Get App ID from a filename.
        /// </summary>
        /// <param name="filename">The filename to convert.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The App ID.</returns>
        public static NtResult<string> GetAppIdFromFileName(string filename, bool throw_on_error)
        {
            return FirewallNativeMethods.FwpmGetAppIdFromFileName0(filename, out SafeFwpmMemoryBuffer appid).CreateWin32Result(
                throw_on_error, () => {
                using (appid)
                {
                    appid.Initialize<FWP_BYTE_BLOB>(1);
                    var blob = appid.Read<FWP_BYTE_BLOB>(0);
                    return Encoding.Unicode.GetString(blob.ToArray()).TrimEnd('\0');
                }
            });
        }

        /// <summary>
        /// Get App ID from a filename.
        /// </summary>
        /// <param name="filename">The filename to convert.</param>
        /// <returns>The App ID.</returns>
        public static string GetAppIdFromFileName(string filename)
        {
            return GetAppIdFromFileName(filename, true).Result;
        }

        #endregion

        #region Internal Methods
        internal static Guid? ReadGuid(IntPtr ptr)
        {
            if (ptr == IntPtr.Zero)
                return null;
            return (Guid)Marshal.PtrToStructure(ptr, typeof(Guid));
        }
        #endregion
    }
}
