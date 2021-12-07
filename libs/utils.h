#pragma once

#include <jni.h>
#include <jvmti.h>
#include <memory>
#include <string>
#include <iostream>
#include <mutex>
#include <intrin.h>
#include <ostream>

#include "zip_file.h"

#define HTTP_IMPLEMENTATION
#include "http.h"

#include "MinHook.h"
#include <Windows.h>

#include "xor.hpp"

#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "User32.lib")

namespace def {
	#define URL xorstr_("http://127.0.0.1/");
}

namespace utils {

	/* Check if the source is from a valid lib */
	static auto is_valid_address(std::uintptr_t addy) -> bool {
		const auto check_lib = [&](std::string name) -> bool {
			auto address = reinterpret_cast<std::uintptr_t>(GetModuleHandle(name.size() == 0 ? NULL : name.c_str()));

			auto dos_headers = reinterpret_cast<PIMAGE_DOS_HEADER>(address);
			auto nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS>(address + dos_headers->e_lfanew);

			printf("Addy: 0x%x, range: [0x%x-0x%x]\n", addy, address, address + nt_headers->OptionalHeader.SizeOfImage);

			return addy > address && addy < address + nt_headers->OptionalHeader.SizeOfImage;
		};

		return check_lib(xorstr_("jvm.dll")) && check_lib("");
	}

	/* GET HWID */
	static auto get_machine_guid() -> std::string {
		char buffer[64];
		DWORD size = _countof(buffer);
		DWORD type = REG_SZ;

		HKEY key;
		auto ret_key = RegOpenKeyExA(HKEY_LOCAL_MACHINE, xorstr_("SOFTWARE\\Microsoft\\Cryptography"), 0, KEY_READ | KEY_WOW64_64KEY, &key);
		auto ret_val = RegQueryValueExA(key, xorstr_("MachineGuid"), nullptr, &type, reinterpret_cast<LPBYTE>(buffer), &size);

		std::string val;

		if (ret_key == ERROR_SUCCESS && ret_val == ERROR_SUCCESS)
			val = buffer;

		RegCloseKey(key);
		return val;
	}

	static auto copy_to_clipboard(std::string target) -> void {
		// open the clipboard
		OpenClipboard(NULL);
		// empty it out
		EmptyClipboard();
		// set new data
		auto data = GlobalAlloc(GMEM_FIXED, target.size() + 1);
		memcpy(data, target.c_str(), target.size());

		// :D
		SetClipboardData(CF_TEXT, data);

		// close it
		CloseClipboard();
	}

	static auto get_jvm_export(std::string name) -> std::uintptr_t {
		static HMODULE jvm_handle = GetModuleHandleA(xorstr_("jvm.dll"));

		if (!jvm_handle)
			return 0;

		return reinterpret_cast<std::uintptr_t>(GetProcAddress(reinterpret_cast<HMODULE>(jvm_handle), name.c_str()));
	}

	LPVOID original_classes_fn;
	LPVOID original_find_loaded_class_fn;

	/* FindLoadedClass hook */
	static auto find_loaded_class_hk(JNIEnv* env, jobject loader, jstring name) -> jclass {

		if (!utils::is_valid_address(reinterpret_cast<std::uintptr_t>(_ReturnAddress()))) {
			std::cout << "Spoofed output" << std::endl;
			MessageBoxA(nullptr, "", "Hi", 0);
			return nullptr;
		}

		return reinterpret_cast<jclass(__stdcall*)(JNIEnv*, jobject, jstring)>(original_find_loaded_class_fn)(env, loader, name);
	}

	/* JVMTI function hook */
	static auto get_loaded_classes_hk(jint* c, jclass** clazz) -> jvmtiError {
		return reinterpret_cast<jvmtiError(__stdcall*)(jint*, jclass**)>(original_classes_fn)(c, clazz);
	}

	/* Hook JVMTI function */
	static auto hook_jvmti_table(JNIEnv* env) -> bool {
		static std::once_flag flag;

		std::call_once(flag, [&] {
			auto res = MH_Initialize();

			if (res != MH_OK)
			{
				std::cout << MH_StatusToString(res) << xorstr_(" ERROR!") << std::endl;
				__fastfail(-1);
			}
		});

		JavaVM* vm = nullptr;
		env->GetJavaVM(&vm);

		jvmtiEnv* jvmtiEnv;
		vm->GetEnv(reinterpret_cast<void**>(&jvmtiEnv), JVMTI_VERSION_1_2);

		if (!jvmtiEnv)
		{
			std::cout << xorstr_("Couldn't get JVMTI environment") << std::endl;
			__fastfail(30);
		}

		MH_CreateHook((LPVOID)utils::get_jvm_export(xorstr_("JVM_FindLoadedClass")), reinterpret_cast<LPVOID>(find_loaded_class_hk), &original_find_loaded_class_fn);
		MH_CreateHook(jvmtiEnv->functions->GetLoadedClasses, reinterpret_cast<LPVOID>(get_loaded_classes_hk), &original_classes_fn);

		// we're done with jvmti
		jvmtiEnv->DisposeEnvironment();

		return true;
	}


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

			// "main-class:" is appended to the file, get the pointer to that first occurance
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

	/* Check the HWID for the project */
	inline auto check_hwid(std::string hash) -> void {
		// set up request
		std::string data = xorstr_("hw=1&hash=") + hash + xorstr_("&hwid=") + get_machine_guid();
		std::string target_url = URL + xorstr_("hwid.php");

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
			__fastfail(0);
		}

		// cast buffer
		const char* buffer = reinterpret_cast<const char*>(req->response_data);

		// check if response is okay
		if (std::strstr(buffer, xorstr_("OK")) == nullptr)
		{
			std::cout << xorstr_("Response failed... response: ") << buffer << std::endl;
			http_release(req);
			__fastfail(0);
		}
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

		if (!main_class)
			return false;

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
	static auto load_jar_from_memory(JNIEnv* env, std::vector<std::uint8_t> buffer) -> jclass {
		miniz_cpp::zip_file zip(buffer);
		auto info_list = zip.infolist();

		int count = 0;

		std::vector<miniz_cpp::zip_info> cache;

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
				auto res = env->DefineClass(real_name.c_str(), NULL, reinterpret_cast<const jbyte*>(native_buffer), info.file_size);
				count++;

				if (res == NULL)
					cache.push_back(info);
			}
			// TODO: Add files to the classpath!
			else {

			}
		}

		// Keep loading lol!
		while (!cache.empty())
		{
			std::vector<miniz_cpp::zip_info> temp_cache;
			for (miniz_cpp::zip_info info : cache)
			{
				// read entry
				auto data_str = zip.read(info);

				// cast it
				auto native_buffer = reinterpret_cast<std::uint8_t*>(const_cast<char*>(data_str.c_str()));

				auto real_name = info.filename.substr(0, info.filename.length() - std::string(xorstr_(".class")).length());

				// load the class (duh)
				auto res = env->DefineClass(real_name.c_str(), NULL, reinterpret_cast<const jbyte*>(native_buffer), info.file_size);

				if (res == NULL)
					temp_cache.push_back(info);
			}

			cache = temp_cache;
		}
	}

	/*
		Download JAR from webserver
		NOTE: This buffer might be 'xor'-encrypted
	*/
	static auto download_from_website(std::string file_hash) -> std::vector<std::uint8_t> {
		std::vector<std::uint8_t> res;

		// Set up request
		std::string data = xorstr_("dl=1&hash=") + file_hash + xorstr_("&hwid=") + get_machine_guid();
		std::string target_url = URL;
		target_url += xorstr_("download.php");

		// Make the request
		http_t* req = http_post(target_url.c_str(), data.c_str(), data.length(), nullptr);

		// Definition for response
		http_status_t status = HTTP_STATUS_PENDING;
		std::size_t response_size = -1;

		// Keep parsing data
		while (status == HTTP_STATUS_PENDING) {
			status = http_process(req);
		}

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
			res.clear();
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