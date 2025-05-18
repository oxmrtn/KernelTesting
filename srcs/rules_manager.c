#include "../includes/L3SM.h"


bool rule_check_access(kuid_t uid, kgid_t gid, int mask, const char *path)
{
	printk(KERN_INFO "RuleManager: UIS=%d, GID=%d, mask=%d, path=%s\n", __kuid_val(uid), __kgid(gid), mask, path);
	return true;
}

