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

namespace NtApiDotNet
{
    /// <summary>
    /// Static utilities for ALPC.
    /// </summary>
    internal static class NtAlpcUtils
    {
        internal static SafeAlpcMessageAttributesBuffer GetAttributesBuffer(this DisposableList list, IMessageAttributes attrs)
        {
            return attrs == null ? SafeAlpcMessageAttributesBuffer.Null : list.AddResource(attrs.ToSafeBuffer());
        }

        internal static SafeAlpcPortMessageBuffer GetMessageBuffer(this DisposableList list, AlpcMessage message)
        {
            if (message == null)
            {
                return SafeAlpcPortMessageBuffer.Null;
            }
            return list.AddResource(message.ToSafeBuffer());
        }
    }
}
