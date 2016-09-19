//  Copyright 2015 Google Inc. All Rights Reserved.
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//  http ://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

#pragma once

using namespace System;

#include "UserToken.h"

namespace TokenLibrary {

	public enum class LogonType : unsigned int
	{
		Batch,
		Interactive,
		Network,
		NetworkCleartext,
		NewCredentials,
		Service,
	};

	public enum class SaferLevel : unsigned int
	{
		Constrained = 0x10000,
		FullyTrusted = 0x40000,
		NormalUser = 0x20000,
		Untrusted = 0x01000,
	};

	public ref class TokenUtils
	{
	public:
		static UserToken^ GetLogonS4UToken(String^ user, String^ realm, LogonType logonType);
		static UserToken^ GetAnonymousToken();
		static UserToken^ GetLogonUserToken(System::String^ username, System::String^ domain, System::String^ password, 
			array<UserGroup^>^ groups, LogonType logonType);
		static UserToken^ GetTokenFromBits();
		static UserToken^ GetTokenFromThread();
		static UserToken^ GetTokenFromCurrentProcess();
		static UserToken^ GetTokenFromClipboard();
		static UserToken^ CreateProcessForToken(System::String^ cmdline, UserToken^ token, bool make_interactive);
		static UserToken^ GetTokenFromSaferLevel(UserToken^ token, SaferLevel level, bool make_inert);
		static array<UserToken^>^ GetSessionTokens();
    static System::Security::Principal::SecurityIdentifier^ StringSidToSecurityIdentitfier(String^ sid);
	};
}
