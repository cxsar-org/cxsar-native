#pragma once

#include <jni.h>
#include <jvmti.h>
#include <memory>
#include <string>
#include <iostream>
#include <ostream>

#include "zip_file.h"
#include "xor.hpp"

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

	/*
		- Load jar file from memory
	*/
	static auto load_jar_from_memory(JNIEnv* env, jobject loader, std::vector<unsigned char> buffer) {
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
				auto data_str = zip.read(info);

				auto native_buffer = reinterpret_cast<std::uint8_t*>(const_cast<char*>(data_str.c_str()));

				// load the class (duh)
				env->DefineClass(info.filename.c_str(), class_loader, reinterpret_cast<const jbyte*>(native_buffer), info.file_size);
			}
		}

		env->DeleteLocalRef(class_loader);
	}
}