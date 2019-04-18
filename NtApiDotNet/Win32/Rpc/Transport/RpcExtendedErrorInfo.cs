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

using System;
using System.Collections.Generic;
using System.Linq;

namespace NtApiDotNet.Win32.Rpc.Transport
{
    /// <summary>
    /// Extended error information.
    /// </summary>
    public sealed class RpcExtendedErrorInfo
    {
        /// <summary>
        /// Computer name.
        /// </summary>
        public string ComputerName { get; }
        /// <summary>
        /// Process ID.
        /// </summary>
        public int ProcessId { get; }
        /// <summary>
        /// Timestamp.
        /// </summary>
        public DateTime TimeStamp { get; }
        /// <summary>
        /// Generating component.
        /// </summary>
        public int GeneratingComponent { get; }
        /// <summary>
        /// Status code.
        /// </summary>
        public int Status { get; }
        /// <summary>
        /// Detection location.
        /// </summary>
        public int  DetectionLocation { get; }
        /// <summary>
        /// Flags.
        /// </summary>
        public int Flags { get; }
        /// <summary>
        /// Extra parameters.
        /// </summary>
        public IReadOnlyList<object> Parameters { get; }

        private RpcExtendedErrorInfo(ExtendedErrorInfo priv)
        {
            ComputerName = priv.ComputerName.GetString();
            ProcessId = priv.ProcessId;
            TimeStamp = DateTime.FromFileTime(priv.TimeStamp);
            GeneratingComponent = priv.GeneratingComponent;
            Status = priv.Status;
            DetectionLocation = priv.DetectionLocation;
            Flags = priv.Flags;
            Parameters = priv.Params.Select(i => i.GetObject()).ToList();
        }

        internal static IEnumerable<RpcExtendedErrorInfo> ReadErrorInfo(byte[] ndr_data)
        {
            List<RpcExtendedErrorInfo> error_info = new List<RpcExtendedErrorInfo>();
            var priv = ExtendedErrorInfoDecoder.Decode(ndr_data);
            while (priv.HasValue)
            {
                error_info.Add(new RpcExtendedErrorInfo(priv.Value));
                if (priv.Value.Next == null)
                {
                    break;
                }
                priv = priv.Value.Next.GetValue();
            }
            return error_info;
        }
    }
}
