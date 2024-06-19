#pragma once
#include "glib.h"
#include <mono/utils/mono-publib.h>

MONO_BEGIN_DECLS

#if HOST_WIN32

// build for tools
#define  __INTERNAL_USED_BUILD__ 0

// export for UnityEditor...
__declspec(dllexport) int __stdcall mono_assembly_get_status(char* filePath);
__declspec(dllexport) int __stdcall mono_assembly_get_data(char* filePath, void** decrypted_data, uint64_t* decrypted_data_len);
__declspec(dllexport) void __stdcall mono_assembly_data_destroy(uint8_t* buffer);
__declspec(dllexport) int __stdcall mono_assembly_get_data_from_data(char* data, size_t size, void** decrypted_data, uint64_t* decrypted_data_len);

#if __INTERNAL_USED_BUILD__
__declspec(dllexport) int __stdcall mono_encrypt_assembly_file(char* filePath, char* outFile);
__declspec(dllexport) int __stdcall mono_decrypt_assembly_file(char* filePath, char* outFile);
#endif

int __stdcall mono_is_buffer_encrypted(char* data, size_t size);

#endif

MONO_END_DECLS