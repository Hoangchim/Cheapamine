#include <mach-o/dyld.h>
#include <dlfcn.h>
#include "common.h"
#include "hookd_external.h"

static void image_loaded(const struct mach_header *mh, intptr_t vmaddr_slide)
{
	Dl_info imageInfo;
	if (dladdr(mh, &imageInfo) == 0) return;
	if (_dyld_shared_cache_contains_path(imageInfo.dli_fname)) return;

	void *handle = dlopen(imageInfo.dli_fname, RTLD_NOLOAD | RTLD_LAZY | RTLD_FIRST);
	if (!handle) return;

	void **EKHookMemoryRaw_ptr = dlsym(handle, "EKHookMemoryRaw");
	if (EKHookMemoryRaw_ptr) {
		*EKHookMemoryRaw_ptr = litehook_hook_memory_hookd;
	}
	dlclose(handle);
}

void init_hookd_external_support(void)
{
	/*
	 * Cheapamine intentionally keeps the 3.0.10 upstream fixes, but the new
	 * external memory-hook API is not safe for low-cost aftermarket touch stacks.
	 * Keep the runtime override in place for compatibility with Ellekit/Frida
	 * while avoiding the generic "ready" export that triggers the touch freeze
	 * during the environment update flow.
	 */
	_dyld_register_func_for_add_image(image_loaded);
}
