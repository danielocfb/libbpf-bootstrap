// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2019 Facebook */

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/tcp.h>
#include <bpf/bpf.h>

#include "tcp_ca_update.skel.h"

static const unsigned int total_bytes = 10 * 1024 * 1024;
static int expected_stg = 0xeB9F;
static int stop;

#define MIN(x, y) ((x) < (y) ? (x) : (y))

static int settcpca(int fd, const char *tcp_ca)
{
	int err;

	err = setsockopt(fd, IPPROTO_TCP, TCP_CONGESTION, tcp_ca, strlen(tcp_ca));
	if (err != 0) {
    fputs("setsockopt", stderr);
		return -1;
  }

	return 0;
}

int settimeo(int fd, int timeout_ms)
{
	struct timeval timeout = { .tv_sec = 3 };

	if (timeout_ms > 0) {
		timeout.tv_sec = timeout_ms / 1000;
		timeout.tv_usec = (timeout_ms % 1000) * 1000;
	}

	if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout,
		       sizeof(timeout))) {
		fputs("Failed to set SO_RCVTIMEO", stderr);
		return -1;
	}

	if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout,
		       sizeof(timeout))) {
		fputs("Failed to set SO_SNDTIMEO", stderr);
		return -1;
	}

	return 0;
}

static void *server(void *arg)
{
	int lfd = (int)(long)arg, err = 0, fd;
	ssize_t nr_sent = 0, bytes = 0;
	char batch[1500];

	fd = accept(lfd, NULL, NULL);
	while (fd == -1) {
		if (errno == EINTR)
			continue;
		err = -errno;
		goto done;
	}

	if (settimeo(fd, 0)) {
		err = -errno;
		goto done;
	}

	while (bytes < total_bytes && !stop) {
		nr_sent = send(fd, &batch, MIN(total_bytes - bytes, sizeof(batch)), 0);
		if (nr_sent == -1 && errno == EINTR)
			continue;
		if (nr_sent == -1) {
			err = -errno;
			break;
		}
		bytes += nr_sent;
	}

	assert(bytes == total_bytes);

done:
	if (fd >= 0)
		close(fd);
	if (err) {
		stop = 1;
	}
	return NULL;
}

static void do_test(const char *tcp_ca, const struct bpf_map *sk_stg_map)
{
	struct sockaddr_in6 sa6 = {};
	ssize_t nr_recv = 0, bytes = 0;
	int lfd = -1, fd = -1;
	pthread_t srv_thread;
	socklen_t addrlen = sizeof(sa6);
	void *thread_ret;
	char batch[1500];
	int err;

	stop = 0;

	lfd = socket(AF_INET6, SOCK_STREAM, 0);
	if (lfd == -1) {
    fputs("socket (lfd)", stderr);
		return;
  }

	fd = socket(AF_INET6, SOCK_STREAM, 0);
	if (fd == -1) {
    fputs("socket (fd)", stderr);
		close(lfd);
		return;
	}

	if (settcpca(lfd, tcp_ca) || settcpca(fd, tcp_ca) || settimeo(lfd, 0) || settimeo(fd, 0))
		goto done;

	/* bind, listen and start server thread to accept */
	sa6.sin6_family = AF_INET6;
	sa6.sin6_addr = in6addr_loopback;
	err = bind(lfd, (struct sockaddr *)&sa6, addrlen);
	if (err == -1) {
    fputs("bind", stderr);
		goto done;
  }

	err = getsockname(lfd, (struct sockaddr *)&sa6, &addrlen);
	if (err == -1) {
    fputs("getsockname", stderr);
		goto done;
  }

	err = listen(lfd, 1);
	if (err == -1) {
    fputs("listen", stderr);
		goto done;
  }

	if (sk_stg_map) {
		err = bpf_map_update_elem(bpf_map__fd(sk_stg_map), &fd, &expected_stg, BPF_NOEXIST);
		if (err != 0) {
      fputs("bpf_map_update_elem(sk_stg_map)", stderr);
			goto done;
    }
	}

	/* connect to server */
	err = connect(fd, (struct sockaddr *)&sa6, addrlen);
	if (err == -1) {
    fputs("connect", stderr);
		goto done;
  }

	if (sk_stg_map) {
		int tmp_stg;

		err = bpf_map_lookup_elem(bpf_map__fd(sk_stg_map), &fd, &tmp_stg);
		if (err == 0 || errno == ENOENT)
			goto done;
	}

	err = pthread_create(&srv_thread, NULL, server, (void *)(long)lfd);
	if (err == 0)
		goto done;

	/* recv total_bytes */
	while (bytes < total_bytes && !stop) {
		nr_recv = recv(fd, &batch, MIN(total_bytes - bytes, sizeof(batch)), 0);
		if (nr_recv == -1 && errno == EINTR)
			continue;
		if (nr_recv == -1)
			break;
		bytes += nr_recv;
	}

	assert(bytes == total_bytes);

	stop = 1;
	pthread_join(srv_thread, &thread_ret);
	assert(thread_ret != 0);

done:
	close(lfd);
	close(fd);
}

int main(int argc, const char *argv[])
{
	struct tcp_ca_update_bpf *skel;
	struct bpf_link *link;
	int saved_ca1_cnt;
	int err;

	skel = tcp_ca_update_bpf__open_and_load();
	if (skel == NULL) {
    fputs("tcp_ca_update_bpf__open_and_load", stderr);
		return 1;
  }

	link = bpf_map__attach_struct_ops(skel->maps.ca_update_1);
  assert(link != 0);

	do_test("tcp_ca_update", NULL);
	saved_ca1_cnt = skel->bss->ca1_cnt;
	assert(saved_ca1_cnt > 0);

	err = bpf_link__update_map(link, skel->maps.ca_update_2);
	assert(err == 0);

	do_test("tcp_ca_update", NULL);
	assert(skel->bss->ca1_cnt == saved_ca1_cnt);
	assert(skel->bss->ca2_cnt > 0);

	bpf_link__destroy(link);
	tcp_ca_update_bpf__destroy(skel);
	return 0;
}
