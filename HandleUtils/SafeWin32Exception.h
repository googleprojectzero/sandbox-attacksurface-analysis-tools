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

#include <Windows.h>

namespace HandleUtils {
	// This exception will resolve the win32 late so allow it to work 
	// during impersonation.
	public ref class SafeWin32Exception :
		public System::ApplicationException
	{
		unsigned int _last_error;

	public:

		SafeWin32Exception()
		{
			_last_error = ::GetLastError();
		}

		property System::String^ Message {
			virtual System::String^ get() override {
				System::ComponentModel::Win32Exception^ e = gcnew System::ComponentModel::Win32Exception(_last_error);
				return e->Message;
			}
		}
	};

}