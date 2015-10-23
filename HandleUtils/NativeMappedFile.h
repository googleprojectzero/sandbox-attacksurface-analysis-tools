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

public ref class NativeMappedFile : public Microsoft::Win32::SafeHandles::SafeHandleZeroOrMinusOneIsInvalid
{
	long _mapsize;

protected:
	virtual bool ReleaseHandle() override {
		return ::UnmapViewOfFile(this->handle.ToPointer()) == TRUE;
	}

public:

	long GetSize()
	{
		return _mapsize;
	}

	NativeMappedFile(System::IntPtr h, long mapsize) : SafeHandleZeroOrMinusOneIsInvalid(false) {
		this->SetHandle(h);		
		_mapsize = mapsize;
	}

	virtual ~NativeMappedFile() {
	}
};

