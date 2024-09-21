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

namespace NtApiDotNet.Win32.Security.Native
{
    internal enum KERB_PROTOCOL_MESSAGE_TYPE
    {
        KerbDebugRequestMessage,
        KerbQueryTicketCacheMessage,
        KerbChangeMachinePasswordMessage,
        KerbVerifyPacMessage,
        KerbRetrieveTicketMessage,
        KerbUpdateAddressesMessage,
        KerbPurgeTicketCacheMessage,
        KerbChangePasswordMessage,
        KerbRetrieveEncodedTicketMessage,
        KerbDecryptDataMessage,
        KerbAddBindingCacheEntryMessage,
        KerbSetPasswordMessage,
        KerbSetPasswordExMessage,
        KerbVerifyCredentialsMessage,
        KerbQueryTicketCacheExMessage,
        KerbPurgeTicketCacheExMessage,
        KerbRefreshSmartcardCredentialsMessage,
        KerbAddExtraCredentialsMessage,
        KerbQuerySupplementalCredentialsMessage,
        KerbTransferCredentialsMessage,
        KerbQueryTicketCacheEx2Message,
        KerbSubmitTicketMessage,
        KerbAddExtraCredentialsExMessage,
        KerbQueryKdcProxyCacheMessage,
        KerbPurgeKdcProxyCacheMessage,
        KerbQueryTicketCacheEx3Message,
        KerbCleanupMachinePkinitCredsMessage,
        KerbAddBindingCacheEntryExMessage,
        KerbQueryBindingCacheMessage,
        KerbPurgeBindingCacheMessage,
        KerbPinKdcMessage,
        KerbUnpinAllKdcsMessage,
        KerbQueryDomainExtendedPoliciesMessage,
        KerbQueryS4U2ProxyCacheMessage,
        KerbRetrieveKeyTabMessage
    }
}
