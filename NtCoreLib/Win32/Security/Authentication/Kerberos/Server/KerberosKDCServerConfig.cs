//  Copyright 2022 Google LLC. All Rights Reserved.
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

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos.Server
{
    /// <summary>
    /// Configuration for a KDC server.
    /// </summary>
    /// <remarks>This created server is not secure and is designed for testing only. DO NOT use it as a replacement for a proper Kerberos KDC implementation.</remarks>
    public sealed class KerberosKDCServerConfig
    {
        private uint _curr_rid;

        /// <summary>
        /// The krbtgt key.
        /// </summary>
        public KerberosAuthenticationKey KrbTgtKey { get; set; }

        /// <summary>
        /// Specify the listener. If not specified then uses localhost on TCP port 88.
        /// </summary>
        public IKerberosKDCServerListener Listener { get; set; }

        /// <summary>
        /// Specify the domain SID.
        /// </summary>
        public Sid DomainSid { get; set; }

        /// <summary>
        /// The server's default realm.
        /// </summary>
        public string Realm { get; set; }

        /// <summary>
        /// The user database.
        /// </summary>
        public List<KerberosKDCServerUser> Users { get; }

        /// <summary>
        /// Specify additional keys. 
        /// </summary>
        /// <remarks>The key must contain the correct principal name for the key.</remarks>
        public List<KerberosAuthenticationKey> AdditionalKeys { get; }

        /// <summary>
        /// Constructor.
        /// </summary>
        public KerberosKDCServerConfig()
        {
            Users = new List<KerberosKDCServerUser>();
            _curr_rid = 1000;
            Realm = string.Empty;
            AdditionalKeys = new List<KerberosAuthenticationKey>();
        }

        /// <summary>
        /// Add a new user and allocate a RID from the pool.
        /// </summary>
        /// <param name="name">The principal name.</param>
        /// <returns>The created user.</returns>
        public KerberosKDCServerUser AddUser(string name)
        {
            var ret = new KerberosKDCServerUser(name);
            ret.UserId = _curr_rid++;
            Users.Add(ret);
            return ret;
        }

        /// <summary>
        /// Create a basic server based on this configuration.
        /// </summary>
        /// <returns>The KDC server.</returns>
        public KerberosKDCServer Create()
        {
            return new KerberosKDCServerImpl((KerberosKDCServerConfig)MemberwiseClone());
        }
    }
}
