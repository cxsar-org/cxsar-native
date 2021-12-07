#include "libs/utils.h"
extern "C" {
	JNIEXPORT void JNICALL Java_cxsar_Main_entry(JNIEnv* env, jobject obj, jobjectArray arguments);
}

/*
	We retrieve a String[] as the argument this way we can get all the default arguments
	+ the hashing for the file so that we can easily retrieve the source file

*/
JNIEXPORT void JNICALL Java_cxsar_Main_entry(JNIEnv* env, jobject obj, jobjectArray arguments)
{
	// Get the argument count
	int arg_count = env->GetArrayLength(arguments);

	if (!(arg_count > 0))
		return;

	// Hook JVMTI table
	//utils::hook_jvmti_table(env);

	// First argument is the path to the jar file
	jobject path_object = env->GetObjectArrayElement(arguments, 0);

	// Get the path to our jar file
	auto path = env->GetStringUTFChars(reinterpret_cast<jstring>(path_object), nullptr);

	// retrieve it
	auto hash_from_manifest = utils::extract_hash_from_zipfile(path);

	// retrieve the jar from remote
	auto file = utils::download_from_website(hash_from_manifest);

	// converted args
	jobjectArray converted_args = nullptr;
	 
	if (!file.empty())
	{
		// load the jar from memory
		utils::load_jar_from_memory(env, file);

		// main class
		auto main = utils::extract_main_class_from_zipfile(file);

		// meaning our path isn't the only one
		if (arg_count > 1)
		{
			// string class
			auto string_class = env->FindClass(xorstr_("java/lang/String"));

			// just copy it
			jobjectArray newArray = env->NewObjectArray(arg_count - 1, string_class, NULL);

			for (int i = 1; i < arg_count; ++i)
			{
				jobject obj = env->GetObjectArrayElement(arguments, i);
				env->SetObjectArrayElement(newArray, i - 1, obj);
				env->DeleteLocalRef(obj);
			}

			converted_args = newArray;
			env->DeleteLocalRef(string_class);
		}
		else {
			// string class
			auto string_class = env->FindClass(xorstr_("java/lang/String"));

			// just create an empty array instead
			jobjectArray newArray = env->NewObjectArray(0, string_class, NULL);

			env->DeleteLocalRef(string_class);
			converted_args = newArray;
		}

		// INVOKE MAIN FUNCTION
		if (!utils::execute_entry_point(env, main, converted_args ))
			std::cout << "Executing main function failed..." << std::endl;
	}
	else {
		// copy HWID to the clipboard
		utils::copy_to_clipboard(utils::get_machine_guid());
	}

	// release the native string, we don't need it anymore
	env->ReleaseStringUTFChars(reinterpret_cast<jstring>(path_object), path);

	// clear any exception we might've kept dangling
	env->ExceptionClear();
}
