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

using NtApiDotNet.Utilities.Data;
using NtApiDotNet.Win32.Security.Buffers;

namespace NtApiDotNet.Win32.Security.Authentication.Schannel
{
    /// <summary>
    /// Base class for an Schannel Control Token.
    /// </summary>
    public abstract class SchannelControlToken : ControlToken
    {
        private protected abstract void WriteBuffer(DataWriter writer);

        /// <summary>
        /// Convert the token into a security buffer.
        /// </summary>
        /// <returns>The security buffer.</returns>
        public override SecurityBuffer ToBuffer()
        {
            DataWriter writer = new DataWriter();
            WriteBuffer(writer);
            return new SecurityBufferInOut(SecurityBufferType.Token | SecurityBufferType.ReadOnly, writer.ToArray());
        }
    }
}
