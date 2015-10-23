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

#include "stdafx.h"
#include "ObjectTypeInfo.h"
#include "typed_buffer.h"
#include "WindowsInternals.h"

using namespace System::Collections::Generic;
using namespace System;

void ObjectTypeInfo::LoadTypes()
{
	if (_types == nullptr)
	{
		_types = gcnew Dictionary<System::String^, ObjectTypeInfo^>(StringComparer::OrdinalIgnoreCase);

		ULONG returnLength;

		DEFINE_NTDLL(NtQueryObject);

		typed_buffer_ptr<HandleUtils::OBJECT_ALL_TYPES_INFORMATION> types_buffer(sizeof(ULONG));
		NTSTATUS status = fNtQueryObject(nullptr, ObjectAllInformation,
			types_buffer, (ULONG)types_buffer.size(), &returnLength);
		size_t alignment = sizeof(void*) - 1;

		if (status == STATUS_INFO_LENGTH_MISMATCH)
		{
			types_buffer.reset(returnLength);

			status = fNtQueryObject(
				nullptr,
				ObjectAllInformation,
				types_buffer,
				(ULONG)types_buffer.size(),
				&returnLength
				);

			if (NT_SUCCESS(status))
			{
				HandleUtils::OBJECT_TYPE_INFORMATION* current_type = types_buffer->TypeInformation;

				for (ULONG count = 0; count < types_buffer->NumberOfTypes; ++count)
				{
					ObjectTypeInfo^ info = gcnew ObjectTypeInfo();

					info->_name = UnicodeNameToString(current_type->Name);
					info->_security_required = !!current_type->SecurityRequired;
					info->_valid_access_mask = current_type->ValidAccess;
					info->_generic_read_mapping = current_type->GenericMapping.GenericRead;
					info->_generic_write_mapping = current_type->GenericMapping.GenericWrite;
					info->_generic_all_mapping = current_type->GenericMapping.GenericAll;
					info->_generic_execute_mapping = current_type->GenericMapping.GenericExecute;
					info->_total_number_of_objects = current_type->TotalNumberOfObjects;
					info->_total_number_of_handles = current_type->TotalNumberOfHandles;
					info->_total_paged_pool_usage = current_type->TotalPagedPoolUsage;
					info->_total_non_paged_pool_usage = current_type->TotalNonPagedPoolUsage;
					info->_total_name_pool_usage = current_type->TotalNamePoolUsage;
					info->_total_handle_table_usage = current_type->TotalHandleTableUsage;
					info->_high_water_number_of_objects = current_type->HighWaterNumberOfObjects;
					info->_high_water_number_of_handles = current_type->HighWaterNumberOfHandles;
					info->_high_water_paged_pool_usage = current_type->HighWaterPagedPoolUsage;
					info->_high_water_non_paged_pool_usage = current_type->HighWaterNonPagedPoolUsage;
					info->_high_water_name_pool_usage = current_type->HighWaterNamePoolUsage;
					info->_high_water_handle_table_usage = current_type->HighWaterHandleTableUsage;
					info->_invalid_attributes = current_type->InvalidAttributes;
					info->_maintain_handle_count = !!current_type->MaintainHandleCount;
					info->_maintain_type_list = current_type->MaintainTypeList;
					info->_pool_type = current_type->PoolType;
					info->_paged_pool_usage = current_type->PagedPoolUsage;
					info->_non_paged_pool_usage = current_type->NonPagedPoolUsage;

					_types[info->Name] = info;

					size_t offset = (current_type->Name.MaximumLength + alignment) & ~alignment;
					BYTE* next_type = reinterpret_cast<BYTE*>(current_type->Name.Buffer) +
						offset;
					current_type = reinterpret_cast<HandleUtils::OBJECT_TYPE_INFORMATION*>(next_type);
				}
			}
		}
	}
}

ObjectTypeInfo^ ObjectTypeInfo::GetTypeByName(System::String^ name)
{	
	LoadTypes();

	if (_types->ContainsKey(name))
	{
		return _types[name];
	}
	else
	{
		return nullptr;
	}
}

System::Collections::Generic::IEnumerable<ObjectTypeInfo^>^ ObjectTypeInfo::GetTypes()
{	
	LoadTypes();

	return _types->Values;
}

unsigned int ObjectTypeInfo::MapGenericRights(unsigned int access_mask)
{
	GENERIC_MAPPING mapping;
	DWORD ret = access_mask;

	mapping.GenericRead = _generic_read_mapping;
	mapping.GenericWrite = _generic_write_mapping;
	mapping.GenericAll = _generic_all_mapping;
	mapping.GenericExecute = _generic_execute_mapping;

	MapGenericMask(&ret, &mapping);

	return ret;
}
