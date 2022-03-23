#include "vmlinux.h"
#include "bpf_helpers.h"

char LICENSE[] SEC("license") = "GPL";

struct bpf_map_def SEC("maps") events = {
	.type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(u32),
};

struct execve_entry {
	u64 _unused;
	u64 _unused2;

	const char* filename;
	const char* const* argv;
	const char* const* envp;
};

struct event {
	u32 pid;
	u8 fname[32];
	u8 comm[32];
};

const struct event *unused __attribute__((unused));

SEC("tracepoint/syscalls/sys_enter_execve")
int enter_execve(struct execve_entry *args)
{
	struct event info = {};

	u64 pid_tgid = bpf_get_current_pid_tgid();
	info.pid = pid_tgid & 0xFFFFFFFF;

	bpf_probe_read_user_str(info.fname, sizeof(info.fname), args->filename);

	bpf_get_current_comm(info.comm, sizeof(info.comm));

	bpf_perf_event_output(args, &events, BPF_F_CURRENT_CPU, &info, sizeof(info));

	bpf_printk("hello, world\n");

	return 0;
}
