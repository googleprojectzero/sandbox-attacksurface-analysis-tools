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

public ref class ObjectTypeInfo
{
	System::String^ _name;
	bool _security_required;
	unsigned int _valid_access_mask;
	unsigned int _generic_read_mapping;
	unsigned int _generic_write_mapping;
	unsigned int _generic_execute_mapping;
	unsigned int _generic_all_mapping;
	unsigned int _total_number_of_objects;
	unsigned int _total_number_of_handles;
	unsigned int _total_paged_pool_usage;
	unsigned int _total_non_paged_pool_usage;
	unsigned int _total_name_pool_usage;
	unsigned int _total_handle_table_usage;
	unsigned int _high_water_number_of_objects;
	unsigned int _high_water_number_of_handles;
	unsigned int _high_water_paged_pool_usage;
	unsigned int _high_water_non_paged_pool_usage;
	unsigned int _high_water_name_pool_usage;
	unsigned int _high_water_handle_table_usage;
	unsigned int _invalid_attributes;
	bool _maintain_handle_count;
	unsigned int _maintain_type_list;
	unsigned int _pool_type;
	unsigned int _paged_pool_usage;
	unsigned int _non_paged_pool_usage;

	static System::Collections::Generic::Dictionary<System::String^, ObjectTypeInfo^>^ _types;
	static void LoadTypes();
	
internal:

	ObjectTypeInfo()
	{
	}

public:

	property System::String^ Name {
		System::String^ get() {
			return _name;
		}
	}

	property bool SecurityRequired {
		bool get() {
			return _security_required;
		}
	}

	property unsigned int ValidAccessMask {
		unsigned int get() {
			return _valid_access_mask;
		}
	}

	property unsigned int GenericReadMapping {
		unsigned int get() {
			return _generic_read_mapping;
		}
	}

	property unsigned int GenericWriteMapping {
		unsigned int get() {
			return _generic_write_mapping;
		}
	}

	property unsigned int GenericExecuteMapping {
		unsigned int get() {
			return _generic_execute_mapping;
		}
	}

	property unsigned int GenericAllMapping {
		unsigned int get() {
			return _generic_all_mapping;
		}
	}

	property unsigned int TotalNumberOfObjects { unsigned int get() { return _total_number_of_objects; } }
	property unsigned int TotalNumberOfHandles { unsigned int get() { return _total_number_of_handles; } }
	property unsigned int TotalPagedPoolUsage { unsigned int get() { return _total_paged_pool_usage; } }
	property unsigned int TotalNonPagedPoolUsage { unsigned int get() { return _total_non_paged_pool_usage; } }
	property unsigned int TotalNamePoolUsage { unsigned int get() { return _total_name_pool_usage; } }
	property unsigned int TotalHandleTableUsage { unsigned int get() { return _total_handle_table_usage; } }
	property unsigned int HighWaterNumberOfObjects { unsigned int get() { return _high_water_number_of_objects; } }
	property unsigned int HighWaterNumberOfHandles { unsigned int get() { return _high_water_number_of_handles; } }
	property unsigned int HighWaterPagedPoolUsage { unsigned int get() { return _high_water_paged_pool_usage; } }
	property unsigned int HighWaterNonPagedPoolUsage { unsigned int get() { return _high_water_non_paged_pool_usage; } }
	property unsigned int HighWaterNamePoolUsage { unsigned int get() { return _high_water_name_pool_usage; } }
	property unsigned int HighWaterHandleTableUsage { unsigned int get() { return _high_water_handle_table_usage; } }
	property unsigned int InvalidAttributes { unsigned int get() { return _invalid_attributes; } }
	property bool MaintainHandleCount { bool get() { return _maintain_handle_count; } }
	property unsigned int MaintainTypeList { unsigned int get() { return _maintain_type_list; } }
	property unsigned int PoolType { unsigned int get() { return _pool_type; } }
	property unsigned int PagedPoolUsage { unsigned int get() { return _paged_pool_usage; } }
	property unsigned int NonPagedPoolUsage { unsigned int get() { return _non_paged_pool_usage; } }

	bool HasReadPermission(unsigned int access_mask)
	{
		return (access_mask & _generic_read_mapping) != 0;
	}

	bool HasWritePermission(unsigned int access_mask)
	{
		return (access_mask & _generic_write_mapping & 0xFFFF) != 0;
	}

	bool HasExecutePermission(unsigned int access_mask)
	{
		return (access_mask & _generic_execute_mapping & 0xFFFF) != 0;
	}

	bool HasFullPermission(unsigned int access_mask)
	{
		return (access_mask == _generic_all_mapping);
	}

	unsigned int MapGenericRights(unsigned int access_mask);

	static ObjectTypeInfo^ GetTypeByName(System::String^ name);
	static System::Collections::Generic::IEnumerable<ObjectTypeInfo^>^ GetTypes();
};

