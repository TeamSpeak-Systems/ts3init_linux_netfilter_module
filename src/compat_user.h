/*
 *	Userspace-level compat hacks
 */
#ifndef _XTABLES_COMPAT_USER_H
#define _XTABLES_COMPAT_USER_H 1

/* linux-glibc-devel 2.6.34 header screwup */
#ifndef ALIGN
#	define ALIGN(s, n) (((s) + ((n) - 1)) & ~((n) - 1))
#endif

#endif /* _XTABLES_COMPAT_USER_H */
