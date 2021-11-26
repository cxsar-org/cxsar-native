#pragma once

#include <jni.h>
#include <jvmti.h>
#include <memory>
#include <string>
#include <iostream>
#include <ostream>

#include "zip_file.h"
#include "http.h"
#include "xor.hpp"

namespace def {
	#define URL xorstr_("http://127.0.0.1/");
}

namespace utils {


	/*
		- Retrieve the hash from the manifest inside the jar file
		- Return it
		- That's it

	*/
	static auto extract_hash_from_zipfile(std::string path) -> const char* {
		miniz_cpp::zip_file file(path);

		auto names = file.namelist();

		for (int i = 0; i < names.size(); ++i)
		{
			std::string filename = names[i];

			if (std::strstr(filename.c_str(), xorstr_("MANIFEST.MF")) == nullptr)
				continue;

			auto info = file.getinfo(filename);
			auto content = file.read(info);

			auto hash_str = xorstr("Cxsar-Hash: ");

			// "cxsar-hash:" is appended to the file, get the pointer to that first occurance
			const char* hash_prefix = std::strstr(content.c_str(), hash_str.crypt_get());

			// check if we actually found it
			if (hash_prefix == nullptr) {
				std::cout << xorstr_("Hash not found in manifest, are you sure it's the correct jar file?") << std::endl;
				return xorstr_("None");
			}

			// we did so the hash starts here next
			hash_prefix += hash_str.size();

			// convert it to a C++ string
			// note: every line ends with \r\n so that means this will go to [hash]\r as the string
			std::string native_str = std::string(hash_prefix);
			native_str = native_str.substr(0, native_str.length() - 1);

			return native_str.c_str();
		}

		return xorstr_("None");
	}

	/*
		- Apply xor crypt to vector
		- NOTE: This is not cryptographically safe, however, for the purpose of this project
		it suffices
	
	*/
	static auto xor_crypt_vector(std::vector<std::uint8_t> &buffer, std::string key)
	{
		for (int i = 0; i < buffer.size(); ++i)
			buffer[i] ^= key[i % key.size()];
	}

	/* NOTE: This returns a GLOBAL reference, please clean it up
		using env->DeleteGlobalRef!
	*/
	static auto get_classloader_from_object(JNIEnv* env, jobject obj) -> jobject {
		jclass object_class = env->GetObjectClass(obj);

		if (!object_class)
			return nullptr;

		auto get_classloader_mid = env->GetMethodID(object_class, xorstr_("getClassLoader"), xorstr_("()Ljava/lang/ClassLoader;"));

		if (!get_classloader_mid)
		{
			env->DeleteLocalRef(object_class);
			return nullptr;
		}

		jobject the_classloader = env->CallObjectMethod(obj, get_classloader_mid);

		if (!the_classloader)
		{
			env->DeleteLocalRef(object_class);
			return nullptr;
		}

		return env->NewGlobalRef(the_classloader);
	}

	/*
		- Load jar file from memory
	*/
	static auto load_jar_from_memory(JNIEnv* env, jobject loader, std::vector<std::uint8_t> buffer) {
		miniz_cpp::zip_file zip(buffer);
		auto info_list = zip.infolist();

		jclass secure_classloader_class = env->FindClass(xorstr_("java/security/SecureClassLoader"));
		auto secure_classloader_init = env->GetMethodID(secure_classloader_class, xorstr_("<init>"), xorstr_("(Ljava/lang/ClassLoader;)V"));

		auto class_loader = env->NewObject(secure_classloader_class, secure_classloader_init, loader);

		env->DeleteLocalRef(secure_classloader_class);
		env->DeleteLocalRef(loader);

		// iterate all files
		for (int i = 0; i < info_list.size(); ++i)
		{
			// retrieve info for index
			miniz_cpp::zip_info info = info_list[i];

			// check if the file is a .class file
			if (std::strstr(info.filename.c_str(), xorstr_(".class")) != nullptr)
			{
				// read entry
				auto data_str = zip.read(info);

				auto native_buffer = reinterpret_cast<std::uint8_t*>(const_cast<char*>(data_str.c_str()));

				// load the class (duh)
				// NOTE: might have to optimize this a tad more
				env->DefineClass(info.filename.substr(0, info.filename.length() - std::string(xorstr_(".class")).length()).c_str(), class_loader, reinterpret_cast<const jbyte*>(native_buffer), info.file_size);
			}
		}

		env->DeleteLocalRef(class_loader);
	}

	/*
		Download JAR from webserver
		NOTE: This buffer might be 'xor'-encrypted
	*/
	static auto download_from_website(std::string file_hash) -> std::vector<std::uint8_t> {
		std::vector<std::uint8_t> res;

		// Set up request
		std::string data = xorstr_("target_hash=") + file_hash;
		std::string target_url = URL + xorstr_("dl/");

		// Make the request
		http_t* req = http_post(target_url.c_str(), data.c_str(), data.length(), nullptr);

		// Definition for response
		http_status_t status = HTTP_STATUS_PENDING;
		std::size_t response_size = -1;

		// Keep parsing data
		while (status == HTTP_STATUS_PENDING) status = http_process(req);

		// Check for fail
		if (status == HTTP_STATUS_FAILED)
		{
			std::cout << xorstr_("Couldn't make request to CXSAR (") << req->status_code << xorstr_(") ") << req->reason_phrase << std::endl;
			http_release(req);
			return res;
		}

		// Find the header
		const char* buffer = reinterpret_cast<const char*>(req->response_data);

		// Get the message
		const char* split = std::strchr(buffer, ':');

		// Check the message formatting
		if (split == nullptr)
		{
			std::cout << xorstr_("Incorrect response data!") << std::endl;
			http_release(req);
			return res;
		}

		// Get the message length
		auto message_len = split - buffer;

		// Spawn buffer for the message
		std::unique_ptr<std::uint8_t[]> message_buffer = std::make_unique<std::uint8_t[]>(message_len);

		// Convert the buffer to the actual message
		const char* message = reinterpret_cast<const char*>(message_buffer.get());

		// Error code was given out
		if (strstr(message, xorstr_("OK")) == nullptr)
		{
			std::cout << "Error with request, response: " << message << std::endl;
			http_release(req);
			return res;
		}

		// Jump to next
		buffer = split + message_len;

		// Offset
		std::size_t offset = buffer - req->response_data;

		// Reset the vector
		res.resize(req->response_size - offset);

		// copy response buffer to the vector
		std::memcpy(&res[0], buffer, req->response_size - offset);

		// release and return result
		http_release(req);
		return res;
	}
}