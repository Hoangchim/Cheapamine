#include <mach-o/dyld.h>
#include <dlfcn.h>
#include <stdlib.h>
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
	 * Cheapamine keeps the 3.0.10/3.0.9 hookd path for jailbreak stability, but
	 * the external memory-hook export introduced in the newer Dopamine flow is
	 * not compatible with low-cost aftermarket touch stacks. Leave it disabled by
	 * default and only enable it explicitly when debugging a specific runtime.
	 */
	if (getenv("DOPAMINE_ENABLE_EXTERNAL_HOOKD_SUPPORT") == NULL) {
		return;
	}
	_dyld_register_func_for_add_image(image_loaded);
}
