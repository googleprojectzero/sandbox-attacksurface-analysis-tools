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

using NtApiDotNet.Utilities.Memory;
using NtApiDotNet.Win32;
using System;

namespace NtApiDotNet.Net.Firewall
{
    /// <summary>
    ///  Class to represent an IKEEXT quick mode failure event.
    /// </summary>
    public sealed class FirewallNetEventIkeExtQmFailure : FirewallNetEvent
    {
        /// <summary>
        /// Windows error code for the failure
        /// </summary>
        public Win32Error FailureErrorCode { get; }
        /// <summary>
        /// Point of failure
        /// </summary>
        public IPsecFailurePoint FailurePoint { get; }
        /// <summary>
        /// IKE or Authip.
        /// </summary>
        public IkeExtKeyModuleType KeyingModuleType { get; }
        /// <summary>
        /// Main mode state
        /// </summary>
        public IkeExtQmSaState QmState { get; }
        /// <summary>
        /// Initiator or Responder
        /// </summary>
        public IkeExtSaRole SaRole { get; }

        /// <summary>
        /// Tunnel or transport mode.
        /// </summary>
        public IPsecTrafficType SaTrafficType { get; }

        /// <summary>
        /// Main mode filter ID
        /// </summary>
        public ulong QmFilterId { get; }

        /// <summary>
        /// Local subnet address and mask.
        /// </summary>
        public FirewallAddressAndMask LocalSubNet { get; }

        /// <summary>
        /// Remote subnet address and mask.
        /// </summary>
        public FirewallAddressAndMask RemoteSubNet { get; }

        private static FirewallAddressAndMask GetAddr(FWP_VALUE0 value)
        {
            var v = new FirewallValue(value, Guid.Empty);
            if (v.Value is FirewallAddressAndMask addr)
                return addr;
            return default;
        }

        internal FirewallNetEventIkeExtQmFailure(IFwNetEvent net_event) : base(net_event)
        {
            var ev = net_event.Value.ReadStruct<FWPM_NET_EVENT_IKEEXT_QM_FAILURE0>();
            FailureErrorCode = ev.failureErrorCode;
            FailurePoint = ev.failurePoint;
            KeyingModuleType = ev.keyingModuleType;
            QmState = ev.qmState;
            SaRole = ev.saRole;
            QmFilterId = ev.qmFilterId;
            SaTrafficType = ev.saTrafficType;
            switch (SaTrafficType)
            {
                case IPsecTrafficType.Transport:
                case IPsecTrafficType.Tunnel:
                    {
                        LocalSubNet = GetAddr(ev.localSubNet);
                        RemoteSubNet = GetAddr(ev.remoteSubNet);
                    }
                    break;
            }
        }
    }
}
