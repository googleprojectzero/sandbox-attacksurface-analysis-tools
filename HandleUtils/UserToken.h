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

#include "NativeHandle.h"
#include "ImpersonateProcess.h"

namespace TokenLibrary {

	public enum class TokenType
	{
		Primary,
		Impersonation
	};

	public enum class TokenImpersonationLevel
	{
		None,
		Anonymous,
		Identification,
		Impersonation,
		Delegation
	};

	public enum class TokenElevationType
	{
		Default,
		Full,
		Limited
	};

	[System::Flags]
	public enum class TokenIntegrityLevelPolicy
	{
		Off = 0,
		NoWriteUp = 1,
		NewProcessMin = 2,
	};

	[System::Flags]
	public enum class GroupFlags : unsigned int
	{
		None = 0,
		Mandatory = 0x00000001,
		EnabledByDefault = 0x00000002,
		Enabled = 0x00000004,
		Owner = 0x00000008,
		UseForDenyOnly = 0x00000010,
		Integrity = 0x00000020,
		IntegrityEnabled = 0x00000040,
		LogonId = 0xC0000000,
		Resource = 0x20000000,
	};

	public enum class TokenIntegrityLevel : unsigned int
	{
		Untrusted = SECURITY_MANDATORY_UNTRUSTED_RID,
		Low = SECURITY_MANDATORY_LOW_RID,
		Medium = SECURITY_MANDATORY_MEDIUM_RID,
		High = SECURITY_MANDATORY_HIGH_RID,
		System = SECURITY_MANDATORY_SYSTEM_RID,
	};

	[System::Flags]
	public enum class TokenPrivilegeFlags : unsigned int
	{
		Enabled = SE_PRIVILEGE_ENABLED,
		EnabledByDefault = SE_PRIVILEGE_ENABLED_BY_DEFAULT,
		Removed = SE_PRIVILEGE_REMOVED,
		UsedForAccess = SE_PRIVILEGE_USED_FOR_ACCESS,
	};

	public ref class TokenPrivilege
	{
		System::String^ _name;
		System::String^ _displayName;
		TokenPrivilegeFlags _flags;
		unsigned long long _luid;

	public:
		property TokenPrivilegeFlags Flags {
			TokenPrivilegeFlags get() {
				return _flags;
			}
		}

		property System::String^ Name {
			System::String^ get() {
				return _name;
			}
		}

		property System::String^ DisplayName {
			System::String^ get() {
				return _displayName;
			}
		}

		property unsigned long long Luid {
			unsigned long long get() {
				return _luid;
			}
		}
		
		TokenPrivilege(unsigned long long luid, System::String^ name,
			System::String^ displayName, TokenPrivilegeFlags flags)
		{
			_luid = luid;
			_name = name;
			_displayName = displayName;
			_flags = flags;
		}

		bool IsEnabled()
		{
			return (_flags & TokenPrivilegeFlags::Enabled) == TokenPrivilegeFlags::Enabled;
		}		
	};

	public ref class UserGroup
	{
		System::Security::Principal::SecurityIdentifier^ _sid;
		GroupFlags _flags;

	public:
		property GroupFlags Flags {
			GroupFlags get() {
				return _flags;
			}
		}

		property System::Security::Principal::SecurityIdentifier^ Sid {
			System::Security::Principal::SecurityIdentifier^ get() {
				return _sid;
			}
		}

		UserGroup(System::Security::Principal::SecurityIdentifier^ sid, GroupFlags flags)
		{
			_sid = sid;
			_flags = flags;
		}

		UserGroup(System::IntPtr rawsid, GroupFlags flags) 
			: UserGroup(gcnew System::Security::Principal::SecurityIdentifier(rawsid), flags)
		{

		}

		bool IsEnabled()
		{
			return (_flags & GroupFlags::Enabled) == GroupFlags::Enabled;
		}

		System::String^ GetName()
		{
			try
			{
				System::Security::Principal::NTAccount^ ntacct =
					static_cast<System::Security::Principal::NTAccount^>(_sid->Translate(System::Security::Principal::NTAccount::typeid));

				return ntacct->ToString();
			}
			catch (System::Security::Principal::IdentityNotMappedException^)
			{
				return _sid->ToString();
			}
		}
	};

	public ref class UserToken
	{
		NativeHandle^ _token;
		System::Security::Principal::SecurityIdentifier^ _usersid;

	public:

		UserGroup^ GetUser();		
		TokenType GetTokenType();
		TokenImpersonationLevel GetImpersonationLevel();
		TokenIntegrityLevel GetTokenIntegrityLevel();		
		void SetTokenIntegrityLevel(TokenIntegrityLevel token_il);
		unsigned long long GetAuthenticationId();
		unsigned long long GetTokenId();
		unsigned long long GetModifiedId();
		int GetSessionId();
		System::String^ GetSourceName();
		unsigned long long GetSourceId();
		unsigned long long GetTokenOriginId();
		UserToken^ GetLinkedToken();
		array<UserGroup^>^ GetGroups();
		array<TokenPrivilege^>^ GetPrivileges();
		UserGroup^ GetDefaultOwner();
		UserGroup^ GetPrimaryGroup();
		System::Security::AccessControl::RawAcl^ GetDefaultDacl();
		bool IsUIAccess();
		bool IsSandboxInert();
		bool IsVirtualizationAllowed();
		bool IsVirtualizationEnabled();

		TokenElevationType GetElevationType();
		bool IsRestricted();
		array<UserGroup^>^ GetRestrictedSids();
		bool IsAppContainer();
		UserGroup^ GetPackageSid();
		unsigned int GetAppContainerNumber();
		array<UserGroup^>^ GetCapabilities();
		UserToken^ DuplicateToken(TokenType type, TokenImpersonationLevel implevel);
		UserToken^ DuplicateToken(TokenType type, TokenImpersonationLevel implevel, TokenIntegrityLevel token_il);
		UserToken^ DuplicateHandle();
		UserToken^ DuplicateHandle(unsigned int access_rights);
		TokenIntegrityLevelPolicy GetIntegrityLevelPolicy();
		ImpersonateProcess^ Impersonate();
		void EnablePrivilege(TokenPrivilege^ priv, bool enable);

		property System::IntPtr Handle 
		{
			System::IntPtr get()
			{
				return _token->DangerousGetHandle();
			}
		}

		void Close()
		{
			_token->Close();
		}

		UserToken(NativeHandle^ token);
		~UserToken();
	};

}

