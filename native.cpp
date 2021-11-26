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

	if (!arg_count > 1)
		return;

	// First argument is the path to the jar file
	jobject path_object = env->GetObjectArrayElement(arguments, 0);

	// Get the path to our jar file
	auto path = env->GetStringUTFChars(reinterpret_cast<jstring>(path_object), nullptr);

	// retrieve it
	auto hash_from_manifest = utils::extract_hash_from_zipfile(path);

	miniz_cpp::zip_file file(path);

	file.printdir(std::cout);

	// release the native string, we don't need it anymore
	env->ReleaseStringUTFChars(reinterpret_cast<jstring>(path_object), path);

	// debugging
	std::cout << hash_from_manifest << std::endl;

}
