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

#include <memory>

template<class T>
class typed_buffer_ptr {
	std::unique_ptr<char[]> buffer_;
	size_t size_;

public:
	typed_buffer_ptr() {
	}

	explicit typed_buffer_ptr(size_t size) {
		reset(size);
	}

	void reset(size_t size) {
		buffer_.reset(new char[size]);
		memset(buffer_.get(), 0, size);
		size_ = size;
	}

	operator T*() {
		return reinterpret_cast<T*>(buffer_.get());
	}

	operator const T*() const {
		return cget();
	}

	char* bytes() {
		return buffer_.get();
	}

	T* operator->() const {
		return reinterpret_cast<T*>(buffer_.get());
	}

	const T* cget() const {
		return interpret_cast<const T*>(buffer_.get());
	}

	typed_buffer_ptr(const typed_buffer_ptr<T>& other) = delete;
	typed_buffer_ptr& typed_buffer_ptr::operator=(const typed_buffer_ptr<T>& other) = delete;

	typed_buffer_ptr(typed_buffer_ptr<T>&& other) {
		buffer_ = std::move(other.buffer_);
		size_ = other.size_;
		other.size_ = 0;
	}

	typed_buffer_ptr& operator=(typed_buffer_ptr<T>&& other) {
		if (this != &other)
		{
			buffer_ = std::move(other.buffer_);
			size_ = other.size_;
			other.size_ = 0;
		}
	}

	size_t size() const {
		return size_;
	}
};
