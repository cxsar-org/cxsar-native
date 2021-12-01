#pragma once

#include <jni.h>
#include <jvmti.h>
#include <memory>
#include <string>
#include <iostream>
#include <ostream>

#include "zip_file.h"

#define HTTP_IMPLEMENTATION
#include "http.h"

#include "xor.hpp"

namespace def {
	#define URL xorstr_("http://127.0.0.1/website/");
}

namespace utils {


	/*
		- Retrieve the hash from the manifest inside the jar file
		- Return it
		- That's it

	*/
	static auto extract_hash_from_zipfile(std::string path) -> std::string {
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
			native_str = native_str.substr(0, native_str.length() - 2);

			return native_str;
		}

		return xorstr_("None");
	}

	/*
		Retrieves the main-class of the parsed zipfile by reading the manifest
		This is basically the same code as extract_hash_from_zipfile
	*/
	static auto extract_main_class_from_zipfile(std::vector<std::uint8_t> buffer) -> std::string {
		miniz_cpp::zip_file file(buffer);

		auto names = file.namelist();

		for (int i = 0; i < names.size(); ++i)
		{
			std::string filename = names[i];

			if (std::strstr(filename.c_str(), xorstr_("MANIFEST.MF")) == nullptr)
				continue;

			auto info = file.getinfo(filename);
			auto content = file.read(info);

			auto main_class_str = xorstr("Main-Class: ");

			// "cxsar-hash:" is appended to the file, get the pointer to that first occurance
			const char* cls_prefix = std::strstr(content.c_str(), main_class_str.crypt_get());

			// check if we actually found it
			if (cls_prefix == nullptr) {
				std::cout << xorstr_("Main class not found in manifest, are you sure it's the correct jar file?") << std::endl;
				return xorstr_("None");
			}

			// we did so the hash starts here next
			cls_prefix += main_class_str.size();

			// convert it to a C++ string
			// note: every line ends with \r\n so that means this will go to [hash]\r as the string
			std::string native_str = std::string(cls_prefix);

			// \r\n\r\n is appended for some reason...
			// imagine debugging for an hour only to find this out :D
			native_str = native_str.substr(0, native_str.length() - 4);

			// replace . with /
			std::replace(native_str.begin(), native_str.end(), '.', '/');

			return native_str;
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

	/*
		Execute the main function!
	*/
	static auto execute_entry_point(JNIEnv* env, std::string class_name, jobjectArray args) -> bool {
		// get the main class
		auto main_class = env->FindClass(class_name.c_str());

		if (!main_class) {
			std::cout << "Couldn't find main class" << std::endl;
			return false;
		}

		// find main method
		auto main = env->GetStaticMethodID(main_class, xorstr_("main"), xorstr_("([Ljava/lang/String;)V"));

		if (!main)
			return false;

		env->CallStaticVoidMethod(main_class, main, args);
		env->DeleteLocalRef(main_class);

		return true;
	}

	/*
		- Load jar file from memory
	*/
	static auto load_jar_from_memory(JNIEnv* env, std::vector<std::uint8_t> buffer) {
		miniz_cpp::zip_file zip(buffer);
		auto info_list = zip.infolist();

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

				// cast it
				auto native_buffer = reinterpret_cast<std::uint8_t*>(const_cast<char*>(data_str.c_str()));

				auto real_name = info.filename.substr(0, info.filename.length() - std::string(xorstr_(".class")).length());

				// load the class (duh)
				// NOTE: might have to optimize this a tad more
				auto res = env->DefineClass(real_name.c_str(), NULL, reinterpret_cast<const jbyte*>(native_buffer), info.file_size);
			}
		}
	}

	/*
		Download JAR from webserver
		NOTE: This buffer might be 'xor'-encrypted
	*/
	static auto download_from_website(std::string file_hash) -> std::vector<std::uint8_t> {
		std::vector<std::uint8_t> res;

		// Set up request
		std::string data = xorstr_("dl=1&hwid=none&hash=") + file_hash;
		std::string target_url = URL;
		target_url += xorstr_("download.php");

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
			std::cout << buffer << std::endl;
			http_release(req);
			return res;
		}

		// Skip the ':'
		split++;

		// calculate size of the response code
		auto response_code_len = (split - buffer);

		// spawn a buffer for it
		std::unique_ptr<std::uint8_t[]> response_code = std::make_unique<std::uint8_t[]>(response_code_len);

		// copy the response code into the buffer
		std::memcpy(response_code.get(), buffer, response_code_len);

		// calculate size of the message
		auto message_len = (buffer + req->response_size) - split;

		// spawn a buffer for the message
		std::unique_ptr<std::uint8_t[]> message_data = std::make_unique<std::uint8_t[]>(message_len);

		// cast message into a character array
		auto message = reinterpret_cast<const char*>(message_data.get());

		// copy the message into the buffer
		std::memcpy(message_data.get(), split, message_len);

		// check the response code for an OK
		if (std::strstr(reinterpret_cast<const char*>(response_code.get()), xorstr_("OK")) == nullptr)
		{
			std::cout << "Error with request, response: " << message << std::endl;
			http_release(req);
			return res;
		}

		// resize response buffer
		res.resize(message_len);

		// copy the buffer into the vector
		std::memcpy(&res[0], message, message_len);

		// release and return result
		http_release(req);
		return res;
	}
}