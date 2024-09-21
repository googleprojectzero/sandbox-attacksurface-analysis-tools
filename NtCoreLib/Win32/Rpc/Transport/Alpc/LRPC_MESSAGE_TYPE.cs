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

namespace NtCoreLib.Win32.Rpc.Transport.Alpc;

internal enum LRPC_MESSAGE_TYPE
{
    lmtRequest = 0,
    lmtBind = 1,
    lmtFault = 2,
    lmtResponse = 3,
    lmtCancel = 4,
    lmtReservedMessage = 5,     // LRPC_ADDRESS::HandleReservedMessageRequest
    lmtCallbackAck = 7,
    lmtCallbackNack = 8,
    lmtCallbackRequest = 9,
    lmtCallbackReply = 10,
    lmtCallbackFault = 11,
    lmtPipePull = 12,
    lmtPipeAck = 13,
}
