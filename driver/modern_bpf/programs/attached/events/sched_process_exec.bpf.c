/*
 * Copyright (C) 2022 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#include <helpers/interfaces/variable_size_event.h>

/* From linux tree: /include/trace/events/sched.h
 * TP_PROTO(struct task_struct *p, pid_t old_pid,
 *		 struct linux_binprm *bprm)
 */
#ifdef CAPTURE_SCHED_PROC_EXEC
/* chose a short name for bpftool debugging*/
SEC("tp_btf/sched_process_exec")
int BPF_PROG(sched_p_exec,
	     struct task_struct *p, pid_t old_pid,
	     struct linux_binprm *bprm)
{
	struct task_struct *task = get_current_task();
	uint32_t flags = 0;
	READ_TASK_FIELD_INTO(&flags, task, flags);

	/* We are not interested in kernel threads. */
	if(flags & PF_KTHREAD)
	{
		return 0;
	}

	struct auxiliary_map *auxmap = auxmap__get();
	if(!auxmap)
	{
		return 0;
	}
	auxmap__preload_event_header(auxmap, PPME_SYSCALL_EXECVE_19_X);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_ERRNO) */
	/* Please note: if this tracepoint is called the `execve/execveat` call
	 * is correctly performed, so the return value will be always 0.
	 */
	auxmap__store_s64_param(auxmap, 0);

	unsigned long arg_start_pointer = 0;
	unsigned long arg_end_pointer = 0;

	/* `arg_start` points to the memory area where arguments start.
	 * We directly read charbufs from there, not pointers to charbufs!
	 * We will store charbufs directly from memory.
	 */
	READ_TASK_FIELD_INTO(&arg_start_pointer, task, mm, arg_start);
	READ_TASK_FIELD_INTO(&arg_end_pointer, task, mm, arg_end);

	unsigned long total_args_len = arg_end_pointer - arg_start_pointer;

	/* Parameter 2: exe (type: PT_CHARBUF) */
	/* We need to extract the len of `exe` arg so we can understand
	 * the overall length of the remaining args.
	 */
	u16 exe_arg_len = auxmap__store_charbuf_param(auxmap, arg_start_pointer, MAX_PROC_EXE, USER);

	/* Parameter 3: args (type: PT_CHARBUFARRAY) */
	/* Here we read the whole array starting from the pointer to the first
	 * element. We could also read the array element per element but
	 * since we know the total len we read it as a `bytebuf`.
	 * The `\0` after every argument is preserved.
	 */
	auxmap__store_bytebuf_param(auxmap, arg_start_pointer + exe_arg_len, (total_args_len - exe_arg_len) & (MAX_PROC_ARG_ENV - 1), USER);

	/* Parameter 4: tid (type: PT_PID) */
	/* this is called `tid` but it is the `pid`. */
	s64 pid = (s64)extract__task_xid_nr(task, PIDTYPE_PID);
	auxmap__store_s64_param(auxmap, pid);

	/* Parameter 5: pid (type: PT_PID) */
	/* this is called `pid` but it is the `tgid`. */
	s64 tgid = (s64)extract__task_xid_nr(task, PIDTYPE_TGID);
	auxmap__store_s64_param(auxmap, tgid);

	/* Parameter 6: ptid (type: PT_PID) */
	/* this is called `ptid` but it is the `pgid`. */
	s64 pgid = (s64)extract__task_xid_nr(task, PIDTYPE_PGID);
	auxmap__store_s64_param(auxmap, pgid);

	/* Parameter 7: cwd (type: PT_CHARBUF) */
	/// TODO: right now we leave the current working directory empty like in the old probe.
	auxmap__store_empty_param(auxmap);

	/* Parameter 8: fdlimit (type: PT_UINT64) */
	unsigned long fdlimit = 0;
	extract__fdlimit(task, &fdlimit);
	auxmap__store_u64_param(auxmap, fdlimit);

	/* Parameter 9: pgft_maj (type: PT_UINT64) */
	unsigned long pgft_maj = 0;
	extract__pgft_maj(task, &pgft_maj);
	auxmap__store_u64_param(auxmap, pgft_maj);

	/* Parameter 10: pgft_min (type: PT_UINT64) */
	unsigned long pgft_min = 0;
	extract__pgft_min(task, &pgft_min);
	auxmap__store_u64_param(auxmap, pgft_min);

	struct mm_struct *mm = NULL;
	READ_TASK_FIELD_INTO(&mm, task, mm);

	/* Parameter 11: vm_size (type: PT_UINT32) */
	u32 vm_size = extract__vm_size(mm);
	auxmap__store_u32_param(auxmap, vm_size);

	/* Parameter 12: vm_rss (type: PT_UINT32) */
	u32 vm_rss = extract__vm_rss(mm);
	auxmap__store_u32_param(auxmap, vm_rss);

	/* Parameter 13: vm_swap (type: PT_UINT32) */
	u32 vm_swap = extract__vm_swap(mm);
	auxmap__store_u32_param(auxmap, vm_swap);

	/* Parameter 14: comm (type: PT_CHARBUF) */
	auxmap__store_charbuf_param(auxmap, (unsigned long)task->comm, TASK_COMM_LEN, KERNEL);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	bpf_tail_call(ctx, &extra_event_prog_tail_table, T1_SCHED_PROC_EXEC);
	return 0;
}

SEC("tp_btf/sched_process_exec")
int BPF_PROG(t1_sched_p_exec,
	     struct task_struct *p, pid_t old_pid,
	     struct linux_binprm *bprm)
{
	struct auxiliary_map *auxmap = auxmap__get();
	if(!auxmap)
	{
		return 0;
	}

	/*=============================== COLLECT PARAMETERS  ===========================*/

	struct task_struct *task = get_current_task();

	/* Parameter 15: cgroups (type: PT_CHARBUFARRAY) */
	auxmap__store_cgroups_param(auxmap, task);

	unsigned long env_start_pointer = 0;
	unsigned long env_end_pointer = 0;

	READ_TASK_FIELD_INTO(&env_start_pointer, task, mm, env_start);
	READ_TASK_FIELD_INTO(&env_end_pointer, task, mm, env_end);

	unsigned long total_env_len = env_end_pointer - env_start_pointer;

	/* Parameter 16: env (type: PT_CHARBUFARRAY) */
	/* Here we read all the array starting from the pointer to the first
	 * element. We could also read the array element per element but
	 * since we know the total len we read it as a `bytebuf`.
	 * The `\0` after every argument are preserved.
	 */
	auxmap__store_bytebuf_param(auxmap, env_start_pointer, total_env_len & (MAX_PROC_ARG_ENV - 1), USER);

	/* Parameter 17: tty (type: PT_INT32) */
	u32 tty = exctract__tty(task);
	auxmap__store_s32_param(auxmap, (s32)tty);

	/* Parameter 18: pgid (type: PT_PID) */
	pid_t pgid = extract__task_xid_vnr(task, PIDTYPE_PGID);
	auxmap__store_s64_param(auxmap, (s64)pgid);

	/* Parameter 19: loginuid (type: PT_INT32) */
	u32 loginuid;
	extract__loginuid(task, &loginuid);
	auxmap__store_s32_param(auxmap, (s32)loginuid);

	/* Parameter 20: flags (type: PT_FLAGS32) */
	u32 flags = 0;
	struct inode *exe_inode = extract__exe_inode_from_task(task);
	struct file *exe_file = extract__exe_file_from_task(task);

	if(extract__exe_writable(task, exe_inode))
	{
		flags |= PPM_EXE_WRITABLE;
	}
	if(extract__exe_upper_layer(exe_inode))
	{
		flags |= PPM_EXE_UPPER_LAYER;
	}
	if(extract__exe_from_memfd(exe_file))
	{
		flags |= PPM_EXE_FROM_MEMFD;
	}

	auxmap__store_u32_param(auxmap, flags);

	/* Parameter 21: cap_inheritable (type: PT_UINT64) */
	u64 cap_inheritable = extract__capability(task, CAP_INHERITABLE);
	auxmap__store_u64_param(auxmap, cap_inheritable);

	/* Parameter 22: cap_permitted (type: PT_UINT64) */
	u64 cap_permitted = extract__capability(task, CAP_PERMITTED);
	auxmap__store_u64_param(auxmap, cap_permitted);

	/* Parameter 23: cap_effective (type: PT_UINT64) */
	u64 cap_effective = extract__capability(task, CAP_EFFECTIVE);
	auxmap__store_u64_param(auxmap, cap_effective);

	/* Parameter 24: exe_file ino (type: PT_UINT64) */
	u64 ino = 0;
	extract__ino_from_inode(exe_inode, &ino);
	auxmap__store_u64_param(auxmap, ino);

	/* Parameter 25: exe_file ctime (last status change time, epoch value in nanoseconds) (type: PT_ABSTIME) */
	struct timespec64 time = { 0, 0 };
	if(bpf_core_type_exists(struct inode))
	{
		BPF_CORE_READ_INTO(&time, exe_inode, i_ctime);
	}
	else
	{
		struct inode___v6_6 *exe_inode_v6_6 = (void *)exe_inode;
		BPF_CORE_READ_INTO(&time, exe_inode_v6_6, __i_ctime);
		time.tv_nsec = time.tv_nsec & ~I_CTIME_QUERIED;
	}
	auxmap__store_u64_param(auxmap, extract__epoch_ns_from_time(time));

	/* Parameter 26: exe_file mtime (last modification time, epoch value in nanoseconds) (type: PT_ABSTIME) */
	BPF_CORE_READ_INTO(&time, exe_inode, i_mtime);
	auxmap__store_u64_param(auxmap, extract__epoch_ns_from_time(time));

	/* Parameter 27: uid (type: PT_UINT32) */
	u32 uid = 0;
	extract__euid(task, &uid);
	auxmap__store_u32_param(auxmap, uid);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	auxmap__finalize_event_header(auxmap);

	auxmap__submit_event(auxmap, ctx);
	return 0;
}
#endif /* CAPTURE_SCHED_PROC_EXEC */
