/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Shared SIGBUS handler and page verification utilities for bench_fault tests.
 *
 * Provides a SIGBUS signal handler that records the faulting address and
 * longjmps back to the test, plus a check_page() helper for verifying
 * page contents byte-by-byte.
 */
#ifndef SIGBUS_UTIL_H
#define SIGBUS_UTIL_H

#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static sigjmp_buf jmp_env;
static volatile sig_atomic_t sigbus_received;
static volatile void *sigbus_addr;

static inline void sigbus_handler(int sig, siginfo_t *si, void *ctx)
{
	(void)sig;
	(void)ctx;
	sigbus_received = 1;
	sigbus_addr = si->si_addr;
	siglongjmp(jmp_env, 1);
}

static inline int install_sigbus_handler(struct sigaction *old_sa)
{
	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));
	sa.sa_sigaction = sigbus_handler;
	sa.sa_flags = SA_SIGINFO;
	sigemptyset(&sa.sa_mask);

	if (sigaction(SIGBUS, &sa, old_sa) < 0) {
		perror("sigaction(SIGBUS)");
		return -1;
	}
	return 0;
}

static inline int check_page(const void *region, size_t page_idx,
		      unsigned char expected, long page_size)
{
	const unsigned char *p = (const unsigned char *)region +
				 page_idx * page_size;

	for (long i = 0; i < page_size; i++) {
		if (p[i] != expected) {
			fprintf(stderr,
				"    FAIL: page %zu offset %ld: got 0x%02x expected 0x%02x\n",
				page_idx, i, p[i], expected);
			return -1;
		}
	}
	return 0;
}

#endif /* SIGBUS_UTIL_H */
