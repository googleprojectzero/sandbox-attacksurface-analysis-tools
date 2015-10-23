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

namespace TokenLibrary
{
	public ref class ProcessMitigations
	{
	public:
		ProcessMitigations(NativeHandle^ process);
		
		property bool DisallowWin32kSystemCalls;
		property bool DepEnabled;
		property bool DisableAtlThunkEmulation;
		property bool DepPermanent;
		property bool EnableBottomUpRandomization;
		property bool EnableForceRelocateImages;
		property bool EnableHighEntropy;
		property bool DisallowStrippedImages;
		property bool RaiseExceptionOnInvalidHandleReference;
		property bool HandleExceptionsPermanentlyEnabled;
		property bool DisableNonSystemFonts;
		property bool AuditNonSystemFontLoading;
		property bool ProhibitDynamicCode;
		property bool DisableExtensionPoints;
		property bool MicrosoftSignedOnly;
	};
}