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

class ScopedHandle
{
	HANDLE g_h;

public:
	ScopedHandle() : g_h(nullptr) {} 
	ScopedHandle(HANDLE h, bool duplicate);	
	void Close();	
	void Reset(ScopedHandle& h);
  void Reset(HANDLE h, bool duplicate);
	bool IsValid() const {
		return (g_h != nullptr) && (g_h != INVALID_HANDLE_VALUE);
	}
	ScopedHandle(const ScopedHandle& other);
	ScopedHandle& operator=(const ScopedHandle& other);

	ScopedHandle(ScopedHandle&& other);	
	ScopedHandle& operator=(ScopedHandle&& other);

	operator HANDLE() const {
		return g_h;
	}	

	operator bool() const {
		return IsValid();
	}

	HANDLE* GetBuffer() {
		return &g_h;
	}

	HANDLE Detach() {
		HANDLE ret = g_h;
		g_h = nullptr;

		return ret;
	}

	HandleUtils::NativeHandle^ DetachAsNativeHandle()
	{
		return gcnew HandleUtils::NativeHandle(System::IntPtr(Detach()));
	}

	~ScopedHandle();
};

