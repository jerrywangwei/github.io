---
layout:     post
title:      异常向量表
date:       2021-02-16
author:     ww
header-img: img/post-bg-cook.jpg
catalog: true
tags:
    - ARMv8
---
# 异常向量表
![route_2](https://cdn.jsdelivr.net/gh/wangwei-wh/images/armv8/route_2.png)

+ 异常向量表存在4张
+ 第一张，对应表中第一行，CPU运行在EL0级别，同时发生异常时未发生异常级别切换，仍然处于EL0级别
+ 第二张，对应表中第二行，CPU运行在EL1/EL2/EL3级别，同时发生异常时未发生异常级别切换
+ 第三张，对应表中第三行，发生异常时发生异常级别切换，发生异常时处于aarch64运行态
+ 第四张，对应表中第四行，发生异常时发生异常级别切换，发生异常时处于aarch32运行态

![exception_route](https://cdn.jsdelivr.net/gh/wangwei-wh/images/armv8/exception_route.png)

+ 第一个红框，在此种配置下，当CPU发生异常时，EL0/EL1会切换至EL1级别
+ 第二个红框，在此种配置下，当CPU发生异常时，EL0/EL1会切换至EL1级别，EL2不发生级别切换
+ Linux内核只支持EL0和EL1，EL0对应用户态，EL1对应内核态，当CPU运行在用户态时，产生的异步异常会导致CPU切换到EL1，当CPU运行在内核态时，产生的异步异常不会导致exception level的切换

```
/*
 * Exception vectors.
 */
	.pushsection ".entry.text", "ax"

	.align	11
SYM_CODE_START(vectors)
	kernel_ventry	1, sync_invalid			// Synchronous EL1t
	kernel_ventry	1, irq_invalid			// IRQ EL1t
	kernel_ventry	1, fiq_invalid			// FIQ EL1t
	kernel_ventry	1, error_invalid		// Error EL1t

	kernel_ventry	1, sync				// Synchronous EL1h
	kernel_ventry	1, irq				// IRQ EL1h
	kernel_ventry	1, fiq_invalid			// FIQ EL1h
	kernel_ventry	1, error			// Error EL1h

	kernel_ventry	0, sync				// Synchronous 64-bit EL0
	kernel_ventry	0, irq				// IRQ 64-bit EL0
	kernel_ventry	0, fiq_invalid			// FIQ 64-bit EL0
	kernel_ventry	0, error			// Error 64-bit EL0

#ifdef CONFIG_COMPAT
	kernel_ventry	0, sync_compat, 32		// Synchronous 32-bit EL0
	kernel_ventry	0, irq_compat, 32		// IRQ 32-bit EL0
	kernel_ventry	0, fiq_invalid_compat, 32	// FIQ 32-bit EL0
	kernel_ventry	0, error_compat, 32		// Error 32-bit EL0
#else
	kernel_ventry	0, sync_invalid, 32		// Synchronous 32-bit EL0
	kernel_ventry	0, irq_invalid, 32		// IRQ 32-bit EL0
	kernel_ventry	0, fiq_invalid, 32		// FIQ 32-bit EL0
	kernel_ventry	0, error_invalid, 32		// Error 32-bit EL0
#endif
SYM_CODE_END(vectors)
```

+ 第一张异常向量表用不上，但是EL0发生异常时会路由至EL1
+ 第二张异常向量表表示CPU处于EL1时，发生异常时仍然处于EL1
+ 第三张异常向量表表示CPU处于aarch64运行态，EL0用户态时发生异常
+ 第四张异常向量表表示CPU处于aarch32运行态，EL0用户态时发生异常

# 异常向量表代码分析

``` linenumbers
#define SYM_CODE_START(name)				\
	SYM_START(name, SYM_L_GLOBAL, SYM_A_ALIGN)

#define SYM_START(name, linkage, align...)		\
	SYM_ENTRY(name, linkage, align)

#define SYM_ENTRY(name, linkage, align...)		\
	linkage(name) ASM_NL				\
	align ASM_NL					\
	name:

#define ASM_NL		 ;

#define SYM_L_GLOBAL(name)			.globl name
#define SYM_L_WEAK(name)			.weak name
#define SYM_L_LOCAL(name)			/* nothing */

#define SYM_A_ALIGN				ALIGN
#define ALIGN __ALIGN
#define __ALIGN		.align 4,0x90
#define __ALIGN_STR	".align 4,0x90"

SYM_CODE_START(vectors)
	.globl vectors ;				\
	.align 4,0x90 ;					\
	vectors:
```

## 用户态处于64位切换至内核态的异常处理：el0_sync

```
/*
 * EL0 mode handlers.
 */
	.align	6
el0_sync:
	kernel_entry 0
	mov	x0, sp
	bl	el0_sync_handler
	b	ret_to_user

asmlinkage void notrace el0_sync_handler(struct pt_regs *regs)
{
	unsigned long esr = read_sysreg(esr_el1);

	switch (ESR_ELx_EC(esr)) {
	case ESR_ELx_EC_SVC64:
		el0_svc(regs);
		break;
	case ESR_ELx_EC_DABT_LOW:
		el0_da(regs, esr);
		break;
	case ESR_ELx_EC_IABT_LOW:
		el0_ia(regs, esr);
		break;
	case ESR_ELx_EC_FP_ASIMD:
		el0_fpsimd_acc(regs, esr);
		break;
	case ESR_ELx_EC_SVE:
		el0_sve_acc(regs, esr);
		break;
	case ESR_ELx_EC_FP_EXC64:
		el0_fpsimd_exc(regs, esr);
		break;
	case ESR_ELx_EC_SYS64:
	case ESR_ELx_EC_WFx:
		el0_sys(regs, esr);
		break;
	case ESR_ELx_EC_SP_ALIGN:
		el0_sp(regs, esr);
		break;
	case ESR_ELx_EC_PC_ALIGN:
		el0_pc(regs, esr);
		break;
	case ESR_ELx_EC_UNKNOWN:
		el0_undef(regs);
		break;
	case ESR_ELx_EC_BTI:
		el0_bti(regs);
		break;
	case ESR_ELx_EC_BREAKPT_LOW:
	case ESR_ELx_EC_SOFTSTP_LOW:
	case ESR_ELx_EC_WATCHPT_LOW:
	case ESR_ELx_EC_BRK64:
		el0_dbg(regs, esr);
		break;
	default:
		el0_inv(regs, esr);
	}
}

```
### ESR_EL1寄存器描述
![esr_el1](https://cdn.jsdelivr.net/gh/wangwei-wh/images/armv8/esr_el1.png)
![esr_el1_2](https://cdn.jsdelivr.net/gh/wangwei-wh/images/armv8/esr_el1_2.png)

+ svc处理
```
void do_el0_svc(struct pt_regs *regs)
{
	sve_user_discard();
	el0_svc_common(regs, regs->regs[8], __NR_syscalls, sys_call_table);
}

static void el0_svc_common(struct pt_regs *regs, int scno, int sc_nr,
			   const syscall_fn_t syscall_table[])
{
	unsigned long flags = current_thread_info()->flags;

	regs->orig_x0 = regs->regs[0];
	regs->syscallno = scno;

	invoke_syscall(regs, scno, sc_nr, syscall_table);

// ...
}

static void invoke_syscall(struct pt_regs *regs, unsigned int scno,
			   unsigned int sc_nr,
			   const syscall_fn_t syscall_table[])
{
	long ret;

	if (scno < sc_nr) {
		syscall_fn_t syscall_fn;
		syscall_fn = syscall_table[array_index_nospec(scno, sc_nr)];
		ret = __invoke_syscall(regs, syscall_fn);
	} else {
		ret = do_ni_syscall(regs, scno);
	}

	if (is_compat_task())
		ret = lower_32_bits(ret);

	regs->regs[0] = ret;
}
```
从syscall_table[array_index_nospec(scno, sc_nr)]中找到系统调用，然后__invoke_syscall(regs, syscall_fn)进行调用

sys_call_table定义：
```
void *sys_call_table[NR_syscalls] = {
	[0 ... NR_syscalls-1] = sys_ni_syscall,
#include <asm/unistd.h>
};
```

系统调用定义如下：
```
#define __NR_restart_syscall 0
__SYSCALL(__NR_restart_syscall, sys_restart_syscall)
#define __NR_exit 1
__SYSCALL(__NR_exit, sys_exit)
#define __NR_fork 2
__SYSCALL(__NR_fork, sys_fork)
#define __NR_read 3
__SYSCALL(__NR_read, sys_read)
#define __NR_write 4
__SYSCALL(__NR_write, sys_write)3
#define __NR_open 5
__SYSCALL(__NR_open, compat_sys_open)
#define __NR_close 6
__SYSCALL(__NR_close, sys_close)
//...

#define __SYSCALL(nr, sym)	asmlinkage long __arm64_##sym(const struct pt_regs *);

```

restart_syscall实现如下：
```
/*
 * System call entry points.
 */

/**
 *  sys_restart_syscall - restart a system call
 */
SYSCALL_DEFINE0(restart_syscall)
{
	struct restart_block *restart = &current->restart_block;
	return restart->fn(restart);
}

#define SYSCALL_DEFINE0(sname)							\
	SYSCALL_METADATA(_##sname, 0);						\
	asmlinkage long __arm64_sys_##sname(const struct pt_regs *__unused);	\
	ALLOW_ERROR_INJECTION(__arm64_sys_##sname, ERRNO);			\
	asmlinkage long __arm64_sys_##sname(const struct pt_regs *__unused)

#define SYSCALL_METADATA(sname, nb, ...)			\
	static const char *types_##sname[] = {			\
		__MAP(nb,__SC_STR_TDECL,__VA_ARGS__)		\
	};							\
	static const char *args_##sname[] = {			\
		__MAP(nb,__SC_STR_ADECL,__VA_ARGS__)		\
	};							\
	SYSCALL_TRACE_ENTER_EVENT(sname);			\
	SYSCALL_TRACE_EXIT_EVENT(sname);			\
	static struct syscall_metadata __used			\
	  __syscall_meta_##sname = {				\
		.name 		= "sys"#sname,			\
		.syscall_nr	= -1,	/* Filled in at boot */	\
		.nb_args 	= nb,				\
		.types		= nb ? types_##sname : NULL,	\
		.args		= nb ? args_##sname : NULL,	\
		.enter_event	= &event_enter_##sname,		\
		.exit_event	= &event_exit_##sname,		\
		.enter_fields	= LIST_HEAD_INIT(__syscall_meta_##sname.enter_fields), \
	};							\
	static struct syscall_metadata __used			\
	  __attribute__((section("__syscalls_metadata")))	\
	 *__p_syscall_meta_##sname = &__syscall_meta_##sname;

#define ALLOW_ERROR_INJECTION(fname, _etype)				\
static struct error_injection_entry __used				\
	__attribute__((__section__("_error_injection_whitelist")))	\
	_eil_addr_##fname = {						\
		.addr = (unsigned long)fname,				\
		.etype = EI_ETYPE_##_etype,				\
	};
```

read实现如下：
```
SYSCALL_DEFINE3(read, unsigned int, fd, char __user *, buf, size_t, count)
{
	return ksys_read(fd, buf, count);
}

#define SYSCALL_DEFINE3(name, ...) SYSCALL_DEFINEx(3, _##name, __VA_ARGS__)

#define SYSCALL_DEFINEx(x, sname, ...)				\
	SYSCALL_METADATA(sname, x, __VA_ARGS__)			\
	__SYSCALL_DEFINEx(x, sname, __VA_ARGS__)

#define __SYSCALL_DEFINEx(x, name, ...)					\
	__diag_push();							\
	__diag_ignore(GCC, 8, "-Wattribute-alias",			\
		      "Type aliasing is used to sanitize syscall arguments");\
	asmlinkage long sys##name(__MAP(x,__SC_DECL,__VA_ARGS__))	\
		__attribute__((alias(__stringify(__se_sys##name))));	\
	ALLOW_ERROR_INJECTION(sys##name, ERRNO);			\
	static inline long __do_sys##name(__MAP(x,__SC_DECL,__VA_ARGS__));\
	asmlinkage long __se_sys##name(__MAP(x,__SC_LONG,__VA_ARGS__));	\
	asmlinkage long __se_sys##name(__MAP(x,__SC_LONG,__VA_ARGS__))	\
	{								\
		long ret = __do_sys##name(__MAP(x,__SC_CAST,__VA_ARGS__));\
		__MAP(x,__SC_TEST,__VA_ARGS__);				\
		__PROTECT(x, ret,__MAP(x,__SC_ARGS,__VA_ARGS__));	\
		return ret;						\
	}								\
	__diag_pop();							\
	static inline long __do_sys##name(__MAP(x,__SC_DECL,__VA_ARGS__))

```

# 参考

[Anatomy of a system call, part 1](https://lwn.net/Articles/604287/)

[Anatomy of a system call, part 2](https://lwn.net/Articles/604515/)

[Linux系统调用详解（实现机制分析）--linux内核剖析（六）](https://blog.csdn.net/gatieme/article/details/50779184)