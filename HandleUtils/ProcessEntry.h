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

#include "NativeHandle.h"
#include "UserToken.h"
#include "ProcessMitigations.h"

namespace TokenLibrary
{
	ref class ProcessEntry;

	public ref class ThreadEntry
	{		
		ProcessEntry^ _process;
		UserToken^ _token;

	public:
		ThreadEntry(int tid, ProcessEntry^ process, UserToken^ token)
		{
			Tid = tid;
			_process = process;
			_token = token;
		}

		property int Tid;

		property UserToken^ Token
		{
			UserToken^ get() {
				return _token;
			}
		}

		property ProcessEntry^ Process
		{
			ProcessEntry^ get() {
				return _process;
			}
		}

		~ThreadEntry()
		{			
			if (_token != nullptr)
			{
				_token->Close();
			}
		}

	};

	public ref class ProcessEntry
	{
		NativeHandle^ _process;
		UserToken^ _token;		

	public:
		ProcessEntry(System::Diagnostics::Process^ process);

		property String^ Name;
		property int Pid;		
		property int SessionId;		

		property NativeHandle^ ProcessHandle
		{
			NativeHandle^ get() {
				return _process;
			}
		}

		property UserToken^ Token
		{
			UserToken^ get() {
				return _token;
			}
		}

		property ProcessMitigations^ Mitigations
		{
			ProcessMitigations^ get() {
				return gcnew ProcessMitigations(_process);
			}
		}

		System::Collections::Generic::List<ThreadEntry^>^ GetThreadsWithTokens();

		static System::Collections::Generic::List<ProcessEntry^>^ GetProcesses();
		static System::Collections::Generic::List<ProcessEntry^>^ GetProcesses(bool all);

		~ProcessEntry()
		{
			if (_process != nullptr)
			{
				_process->Close();
			}

			if (_token != nullptr)
			{
				_token->Close();
			}
		}
	};

}