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

namespace HandleUtils {

	ref class ObjectDirectoryEntry;

	public ref class ObjectDirectory
	{		
		System::String^ _orig_path;
		System::String^ _full_path;
		System::Collections::Generic::List<ObjectDirectoryEntry^>^ _entries;		
		System::String^ _sddl;
		array<unsigned char>^ _sd;

		void PopulateEntries();

	internal:
		ObjectDirectory(System::String^ object_path);

	public:

		void Refresh()
		{
			PopulateEntries();
		}

		property System::String^ FullPath {
			System::String^ get() {
				return _full_path;
			}
		}

		property System::String^ OriginalPath {
			System::String^ get() {
				return _orig_path;
			}
		}

		property array<unsigned char>^ SecurityDescriptor {
			array<unsigned char>^ get() {
				return _sd;
			}
		}

		property System::String^ StringSecurityDescriptor {
			System::String^ get() {
				return _sddl;
			}
		}

		property ObjectDirectory^ ParentDirectory {
			ObjectDirectory^ get() {
				int index = _full_path->LastIndexOf("\\");
				if (index > 0)
				{
					return gcnew ObjectDirectory(_full_path->Substring(0, index));
				}
				else
				{
					return nullptr;
				}
			}
		}

		property System::String^ Name {
			System::String^ get() {
				int index = _full_path->LastIndexOf("\\");
				if (index > 0)
				{
					return _full_path->Substring(index+1);
				}
				else
				{
					return _full_path;
				}
			}
		}

		property System::Collections::Generic::IEnumerable<ObjectDirectoryEntry^>^ Entries {
			System::Collections::Generic::IEnumerable<ObjectDirectoryEntry^>^ get() {
				if (_entries == nullptr) {
					PopulateEntries();
				}
				return _entries->AsReadOnly();
			}
		}

		void EditSecurity(System::IntPtr hwnd, bool writeable)
		{

		}
	};

}