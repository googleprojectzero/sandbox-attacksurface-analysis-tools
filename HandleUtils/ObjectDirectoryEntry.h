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

#include "ObjectDirectory.h"

namespace HandleUtils {

	ref class ObjectDirectory;

	public ref class ObjectDirectoryEntry : public System::IComparable < ObjectDirectoryEntry^ >
	{
	private:
		System::String^ _name;
		System::String^ _type_name;
		ObjectDirectory^ _directory;
		System::String^ _sddl;
		array<unsigned char>^ _sd;

		void ReadSecurityDescriptor();
		void ReadStringSecurityDescriptor();		

	internal:
		ObjectDirectoryEntry(System::String^ name, System::String^ type_name, ObjectDirectory^ directory)
		{
			_name = name;
			_type_name = type_name;
			_directory = directory;
		}

	public:

		property System::String^ ObjectName {
			System::String^ get() {
				return _name;
			}
		}

		property System::String^ TypeName {
			System::String^ get() {
				return _type_name;
			}
		}

		property bool IsDirectory {
			bool get() {
				return _type_name->Equals("Directory", System::StringComparison::OrdinalIgnoreCase);				
			}
		}

		property bool IsSymlink {
			bool get() {
				return _type_name->Equals("SymbolicLink", System::StringComparison::OrdinalIgnoreCase);
			}
		}	

		property ObjectDirectory^ ParentDirectory {
			ObjectDirectory^ get() {
				return _directory;
			}
		}

		property System::String^ FullPath {
			System::String^ get() {				
				System::String^ base_name = _directory->FullPath->TrimEnd(gcnew array<wchar_t>(1) { '\\' });

				return System::String::Format("{0}\\{1}", base_name, _name);				
			}
		}

		property array<unsigned char>^ SecurityDescriptor {
			array<unsigned char>^ get() {
				if (_sd == nullptr)
				{
					ReadSecurityDescriptor();
				}

				return _sd;
			}
		}

		property System::String^ StringSecurityDescriptor {
			System::String^ get() {
				if (_sddl == nullptr)
				{
					ReadStringSecurityDescriptor();
				}

				return _sddl;
			}
		}

		int GetHashCode() override
		{
			return _name->GetHashCode() ^ _type_name->GetHashCode();
		}

		bool Equals(Object^ other) override
		{
			if (other->GetType() == ObjectDirectoryEntry::typeid)
			{
				ObjectDirectoryEntry^ other_entry = safe_cast<ObjectDirectoryEntry^>(other);

				return _name->Equals(other_entry->_name) && _type_name->Equals(other_entry->_type_name);
			}
			else
			{
				return false;
			}
		}

		virtual int CompareTo(ObjectDirectoryEntry^ other)
		{
			int ret = this->_name->CompareTo(other->_name);

			if (ret == 0)
			{
				ret = this->_type_name->CompareTo(other->_type_name);
			}

			return ret;
		}
	};

}