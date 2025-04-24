#include <linux/module.h>
#include <linux/init.h>
#include <linux/lsm_hooks.h>
#include <linux/fs.h>
#include <linux/cred.h>
#include <linux/sched.h>
#include <linux/namei.h>
#include <linux/security.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Maelys");
MODULE_DESCRIPTION("LSM hook");

static char *get_path_from_inode(struct inode *inode, char *buf, int buflen) {
	struct path path;
	char *tmp;

	path.mnt = NULL;
	path.dentry = d_find_alias(inode);
	if(!path.dentry)
		return NULL;
	tmp = d_path(&path, buf, buflen);
	dput(path.dentry);
	return tmp;
}

static int my_inode_permission(struct inode *inode, int mask)
{
	const struct cred *cred = current_cred();
	printk(KERN_INFO "[my_lsm] PID %d (%s) requested permission mask 0x%x on inode %lu\n", current->pid, current->comm, mask, inode->i_ino);
	char path_buf[512];
	char *path = get_path_from_inode(inode, path_buf, sizeof(path_buf));
	if (!path)
		path = "unknow";

	bool allowed = rule_check_access(cred->uid, cred->gid, mask, path);
	if(!allowed){
		printk(KERN_WARNING "LSMHook: acess denied by rule manager\n");
		return -EACCES;
	}
	return 0;
}

static struct security_hook_list my_hooks[] = {
	LSM_HOOK_INIT(inode_permission, my_inode_permission),
};

static struct lsm_id my_lsm_id = {
	.name = "my_lsm",
};

static int __init my_lsm_init(void)
{
	printk(KERN_INFO "[my_lsm] Initializing LSM hooks\n");
	security_add_hooks(my_hooks, ARRAY_SIZE(my_hooks), &my_lsm_id);
	return 0;
}

DEFINE_LSM(my_lsm) = {
	.name = "my_lsm",
	.init = my_lsm_init,
};
