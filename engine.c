/*
 * Copyright (c) 2025 Henry Ford <fordhenry2299@gmail.com>

 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.

 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/uio.h>

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <imsg.h>
#include <libgen.h>
#include <limits.h>
#include <netdb.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tls.h>
#include <unistd.h>

#include "engine.h"
#include "imsg-blocking.h"

#define SOCKET_ERR_READ 0
#define SOCKET_ERR_WRITE 1

#define min(a, b) ((a) < (b) ? (a) : (b))
#define nitems(a) (sizeof((a)) / sizeof(*(a)))

static void fatal(int, const char *, ...)
	__attribute__((noreturn));
static void fatalc(int, int, const char *, ...)
	__attribute__((noreturn));
static void fatalx(int, const char *, ...)
	__attribute__((noreturn));
static void socket_read_all(int, struct tls *, void *, size_t);
static void tls_fatal(int, struct tls *, const char *);

static const struct http_response_code {
	const char *ident;
	int code;
} http_response_codes[] = {
	{ "Forbidden", 403 },
	{ "Not found", 404 },
};

static struct imsgbuf msgbuf;

static void
fatal(int ex, const char *fmt, ...)
{
	va_list ap;
	int n;
	char buf[ENGINE_ERROR_MAX];

	va_start(ap, fmt);
	memset(buf, 0, sizeof(buf));
	n = vsnprintf(buf, sizeof(buf), fmt, ap);
	if (n < 0) {
		strlcpy(buf, "snprintf", sizeof(buf));
	}
	if ((size_t)n >= sizeof(buf))
		strlcpy(buf, "error message too long", sizeof(buf));
	else if (strlcat(buf, ": ", sizeof(buf)) >= sizeof(buf)
		    || strlcat(buf, strerror(errno), sizeof(buf)) >= sizeof(buf))
		strlcpy(buf, "error message too long", sizeof(buf));

	if (imsg_compose(&msgbuf, ENGINE_IMSG_ERROR, 0, -1, -1,
			 buf, sizeof(buf)) == -1)
		exit(ex);
	if (imsgbuf_flush(&msgbuf) == -1)
		exit(ex);
	exit(ex);
}

static void
fatalc(int ex, int ecode, const char *fmt, ...)
{
	va_list ap;
	int n;
	char buf[ENGINE_ERROR_MAX];

	va_start(ap, fmt);
	memset(buf, 0, sizeof(buf));
	n = vsnprintf(buf, sizeof(buf), fmt, ap);
	if (n < 0) {
		strlcpy(buf, "snprintf", sizeof(buf));
	}
	if ((size_t)n >= sizeof(buf))
		strlcpy(buf, "error message too long", sizeof(buf));
	else if (strlcat(buf, ": ", sizeof(buf)) >= sizeof(buf)
		    || strlcat(buf, strerror(ecode), sizeof(buf)) >= sizeof(buf))
		strlcpy(buf, "error message too long", sizeof(buf));

	if (imsg_compose(&msgbuf, ENGINE_IMSG_ERROR, 0, -1, -1,
			 buf, sizeof(buf)) == -1)
		exit(ex);
	if (imsgbuf_flush(&msgbuf) == -1)
		exit(ex);
	exit(ex);
}

static void
fatalx(int ex, const char *fmt, ...)
{
	va_list ap;
	int n;
	char buf[ENGINE_ERROR_MAX];

	va_start(ap, fmt);
	memset(buf, 0, sizeof(buf));
	n = vsnprintf(buf, sizeof(buf), fmt, ap);
	if (n < 0) {
		strlcpy(buf, "snprintf", sizeof(buf));
	}
	if ((size_t)n >= sizeof(buf))
		strlcpy(buf, "error message too long", sizeof(buf));

	if (imsg_compose(&msgbuf, ENGINE_IMSG_ERROR, 0, -1, -1,
			 buf, sizeof(buf)) == -1)
		exit(ex);
	if (imsgbuf_flush(&msgbuf) == -1)
		exit(ex);
	exit(ex);
}

static void
socket_fatal(int ex, struct tls *tls, int type)
{
	const char *message;

	switch (type) {
	case SOCKET_ERR_READ:
		if (tls != NULL)
			message = "tls_read";
		else
			message = "read";
		break;
	case SOCKET_ERR_WRITE:
		if (tls != NULL)
			message = "tls_write";
		else
			message = "write";
		break;
	}

	if (tls != NULL)
		tls_fatal(ex, tls, message);
	else
		fatal(1, "%s", message);
}

static int
socket_getc(int sock, struct tls *tls)
{
	char ch;

	socket_read_all(sock, tls, &ch, 1);
	return ch;
}

static void
socket_printf(int sock, struct tls *tls, const char *fmt, ...)
{
	char *message, *messagep;
	va_list ap;
	int len;

	va_start(ap, fmt);
	if ((len = vasprintf(&message, fmt, ap)) == -1)
		fatal(1, NULL);

	messagep = message;
	while (len != 0) {
		ssize_t n;

		if (tls != NULL) {
			n = tls_write(tls, messagep, len);
			if (n == TLS_WANT_POLLIN || n == TLS_WANT_POLLOUT)
				continue;
		}
		else
			n = write(sock, messagep, len);

		if (n == -1)
			socket_fatal(1, tls, SOCKET_ERR_WRITE);
		messagep += n;
		len -= n;
	}

	free(message);
	va_end(ap);
}

/*
 * XXX: reads should be buffered.
 * There are a lot of single byte reads, so it is wasteful to call
 * read(2) or tls_read(3) directly.
 */

static ssize_t
socket_read(int sock, struct tls *tls, void *buf, size_t bufsz)
{
	size_t nread;

	nread = 0;
	while (bufsz != 0) {
		ssize_t n;

		if (tls != NULL) {
			n = tls_read(tls, buf, bufsz);
			if (n == TLS_WANT_POLLIN || n == TLS_WANT_POLLOUT)
				continue;
		}
		else
			n = read(sock, buf, bufsz);

		if (n == -1)
			socket_fatal(1, tls, SOCKET_ERR_READ);
		if (n == 0)
			break;
		buf = (char *)buf + n;
		bufsz -= n;
		nread += n;
	}

	return nread;
}

static void
socket_read_all(int sock, struct tls *tls, void *buf, size_t bufsz)
{
	ssize_t n;

	n = socket_read(sock, tls, buf, bufsz);
	if ((size_t)n != bufsz)
		fatalx(1, "connection ended early");
}

static void
socket_skip_space(int sock, struct tls *tls)
{
	int ch;

	ch = socket_getc(sock, tls);
	if (ch != ' ')
		fatalx(1, "whitespace missing");
}

static void
tls_fatal(int ex, struct tls *tls, const char *message)
{
	const char *error;

	error = tls_error(tls);
	if (error == NULL)
		fatalx(ex, "%s", message);
	else	
		fatalx(ex, "%s: %s", message, error);
}

static void
tls_config_fatal(int ex, struct tls_config *tls_config, const char *message)
{
	const char *error;

	error = tls_config_error(tls_config);
	if (error == NULL)
		fatalx(ex, "%s", message);
	else
		fatalx(ex, "%s: %s", message, error);
}

int
main(int argc, char *argv[])
{
	struct imsg msg;
	struct tls_config *tls_config;
	FILE *output_file_orig;
	int n;

	if (argc != 2 || strcmp(argv[1], "-r") != 0)
		errx(1, "nwf-engine should not be run directly");

	if (imsgbuf_init(&msgbuf, 3) == -1)
		exit(1);
	imsgbuf_allow_fdpass(&msgbuf);

	if ((tls_config = tls_config_new()) == NULL)
		fatalx(1, "tls_config_new");
	if (tls_config_set_ca_file(tls_config, tls_default_ca_cert_file()) == -1)
		tls_config_fatal(1, tls_config, "tls_config_set_ca_file");

	if (pledge("stdio inet dns recvfd", NULL) == -1)
		fatal(1, "pledge");

	n = imsg_get_blocking(&msgbuf, &msg);
	if (n == -1)
		fatal(1, "imsg_get_blocking");
	if (n == 0)
		fatalx(1, "imsg_get_blocking EOF");
	if (imsg_get_type(&msg) == ENGINE_IMSG_FILE_STDOUT) {
		if (pledge("stdio inet dns", NULL) == -1)
			fatal(1, "pledge");
		output_file_orig = stdout;
	}
	else if (imsg_get_type(&msg) == ENGINE_IMSG_FILE) {
		int output_fd;

		if (pledge("stdio inet dns", NULL) == -1)
			fatal(1, "pledge");

		if ((output_fd = imsg_get_fd(&msg)) == -1)
			errx(1, "parent sent file message without fd");
		if ((output_file_orig = fdopen(output_fd, "w")) == NULL)
			err(1, "fdopen");
	}
	else if (imsg_get_type(&msg) == ENGINE_IMSG_NEED_PATH) {
		output_file_orig = NULL;
	}
	else
		fatalx(1, "parent sent unknown imsg type");
	imsg_free(&msg);

	for (;;) {
		struct tls *tls;
		FILE *output_file;
		char buf[4096], *path, url[ENGINE_URL_MAX];
		long long content_length, total_read;
		int chunked, connection_close, sock;

		n = imsg_get_blocking(&msgbuf, &msg);
		if (n == -1)
			fatal(1, "imsg_get_blocking");
		if (n == 0)
			break;
		if (imsg_get_type(&msg) != ENGINE_IMSG_DOWNLOAD)
			fatalx(1, "parent sent unknown imsg type");
		if (imsg_get_data(&msg, url, sizeof(url)) == -1)
			fatalx(1, "parent sent data of wrong size");
		if (memchr(url, '\0', sizeof(url)) == NULL)
			fatalx(1, "parent sent string without null terminator");
		imsg_free(&msg);

		for (;;) {
			struct addrinfo hints, *res, *res0;
			char code[4], *host, *port, *proto, *s, version[9];
			int error, save_errno;

			redirected:

			s = url;
			if ((s = strstr(s, "://")) != NULL) {
				*s = '\0';
				s += 3;
				proto = url;
				if (strcmp(proto, "http") != 0 && strcmp(proto, "https") != 0)
					fatalx(1, "unknown protocol '%s'", proto);
			}
			else {
				proto = "http";
				s = url;
			}

			if ((path = strchr(s, '/')) != NULL)
				*path++ = '\0';
			else
				path = "";
			host = s;

			if ((port = strchr(host, ':')) != NULL) {
				*port++ = '\0';
			}
			else {
				port = proto;
			}

			memset(&hints, 0, sizeof(hints));
			hints.ai_family = AF_UNSPEC;
			hints.ai_socktype = SOCK_STREAM;
			hints.ai_protocol = IPPROTO_TCP;

			error = getaddrinfo(host, port, &hints, &res0);
			if (error != 0)
				fatalx(1, "%s: %s", host, gai_strerror(error));

			if (res0 == NULL)
				fatalx(1, "getaddrinfo returned no addresses");
			sock = -1;
			for (res = res0; res != NULL; res = res->ai_next) {
				sock = socket(res->ai_family, res->ai_socktype,
					      res->ai_protocol);
				if (sock == -1)
					fatal(1, "socket");
				if (connect(sock, res->ai_addr,
					    res->ai_addrlen) == -1) {
					switch (errno) {
					case ETIMEDOUT:
					case ECONNREFUSED:
					case EHOSTUNREACH:
						save_errno = errno;
						close(sock);
						sock = -1;
						continue;
					default:
						fatal(1, "%s", host);
					}
				}

				if (!strcmp(proto, "https")) {
					if ((tls = tls_client()) == NULL)
						fatalx(1, "tls_client");
					if (tls_configure(tls, tls_config) == -1)
						tls_config_fatal(1, tls_config, "tls_configure");
					if (tls_connect_socket(tls, sock, host) == -1)
						tls_fatal(1, tls, "tls_connect");
				}
				else {
					tls = NULL;
				}

				break;
			}

			if (sock == -1)
				fatalc(1, save_errno, "%s", host);

			freeaddrinfo(res0);

			socket_printf(sock, tls,
				      "GET /%s HTTP/1.1\r\n"
				      "Host: %s\r\n"
				      "Connection: close\r\n"
				      /*
				       * This is required for some sites
				       * that block requests which do
				       * not include a User-Agent header.
				       * For example https://www.gnu.org
				       * will return 403 forbidden if
				       * it is not set.
				       */
				      "User-Agent: nwf\r\n"
				      "\r\n",
				      path, host);

			socket_read_all(sock, tls, version, sizeof(version) - 1);
			version[sizeof(version) - 1] = '\0';

			if (strncmp(version, "HTTP/1.", 7) != 0)
				fatalx(1, "invalid http version");
			if (version[7] != '0' && version[7] != '1')
				fatalx(1, "invalid http version");

			socket_skip_space(sock, tls);

			socket_read_all(sock, tls, code, sizeof(code) - 1);
			code[sizeof(code) - 1] = '\0';

			if (strcmp(code, "200") != 0 && code[0] != '3') {
				const char *errstr;
				size_t i;
				int response_code;

				response_code = strtonum(code, 100, 599, &errstr);
				if (errstr != NULL)
					fatalx(1, "invalid response code");

				for (i = 0; i < nitems(http_response_codes); i++) {
					if (response_code == http_response_codes[i].code) {
						fatalx(1, "%d %s", response_code,
						     http_response_codes[i].ident);
					}
				}

				fatalx(1, "unknown response code %d", response_code);
			}

			for (;;) {
				if (socket_getc(sock, tls) == '\r')
					if (socket_getc(sock, tls) == '\n')
						break;
			}

			if (!strcmp(code, "200"))
				break;

			for (;;) {
				size_t nread;
				int is_location;
				char location[9];

				nread = 0;
				for (;;) {
					int ch;

					ch = socket_getc(sock, tls);
					if (ch == ':')
						break;
					if (nread != sizeof(location))
						location[nread++] = ch;
				}

				if (nread != sizeof(location)) {
					location[nread] = '\0';
					is_location = !strcasecmp(location, "location");
					nread = 0;
				}
				else
					is_location = 0;

				socket_skip_space(sock, tls);
				for (;;) {
					int ch;

					ch = socket_getc(sock, tls);
					if (ch == '\r')
						if (socket_getc(sock, tls) == '\n')
							break;
					if (is_location) {
						if (nread == sizeof(url) - 1)
							fatalx(1, "redirect url too long");
						url[nread++] = ch;
					}
				}

				if (is_location) {
					url[nread] = '\0';
					if (imsg_compose(&msgbuf,
							 ENGINE_IMSG_REDIRECT,
							 0, -1, -1,
							 url, sizeof(url)) == -1)
						fatal(1, "imsg_compose");
					if (imsgbuf_flush(&msgbuf) == -1)
						fatal(1, "imsgbuf_flush");
					if (tls != NULL) {
						tls_close(tls);
						tls_free(tls);
					}
					close(sock);
					goto redirected;
				}
			}

		}

		if (output_file_orig == NULL) {
			char *base, path_real[PATH_MAX];

			if (strlen(path) == 0)
				fatalx(1, "missing path (use -o)");
			if ((base = basename(path)) == NULL)
				fatal(1, "%s", path);
			memset(path_real, 0, sizeof(path_real));
			if (strlcpy(path_real, base, sizeof(path_real))
				    >= sizeof(path_real))
				fatalx(1, "output path too long");
			if (imsg_compose(&msgbuf, ENGINE_IMSG_PATH, 0, -1, -1,
					 path_real, sizeof(path_real)) == -1)
				fatal(1, "imsg_compose");
		}
		else {
			if (imsg_compose(&msgbuf, ENGINE_IMSG_REDIRECT_OVER, 0,
					 -1, -1, NULL, 0) == -1)
				fatal(1, "imsg_compose");
		}
		if (imsgbuf_flush(&msgbuf) == -1)
			fatal(1, "imsgbuf_flush");

		if (output_file_orig == NULL) {
			int output_fd;

			n = imsg_get_blocking(&msgbuf, &msg);
			if (n == -1)
				fatal(1, "imsg_get_blocking");
			if (n == 0)
				fatalx(1, "imsg_get_blocking EOF");
			if (imsg_get_type(&msg) != ENGINE_IMSG_FILE)
				fatalx(1, "parent sent unknown imsg type");
			if ((output_fd = imsg_get_fd(&msg)) == -1)
				fatalx(1, "parent didnt sent file descriptor");
			if ((output_file = fdopen(output_fd, "w")) == NULL)
				fatal(1, "fdopen");
			imsg_free(&msg);
		}
		else {
			output_file = output_file_orig;
		}

		chunked = 0;
		connection_close = 0;
		content_length = -1;
		for (;;) {
			size_t nread;
			char header_name[18];

			nread = 0;
			for (;;) {
				int ch;

				ch = socket_getc(sock, tls);
				if (ch == '\r') {
					if (nread != 0)
						fatalx(1, "carriage return in header name");
					if (socket_getc(sock, tls) != '\n')
						fatalx(1, "carriage return without linefeed");
					goto done_headers;
				}
				if (ch == ':')
					break;
				if (nread != sizeof(header_name))
					header_name[nread++] = ch;
			}

			if (nread != sizeof(header_name))
				header_name[nread] = '\0';
			else
				header_name[0] = '\0';

			if (!strcasecmp(header_name, "connection")) {
				char close[6];

				nread = 0;
				socket_skip_space(sock, tls);
				for (;;) {
					int ch;

					ch = socket_getc(sock, tls);
					if (ch == '\r') {
						if (socket_getc(sock, tls) != '\n')
							fatalx(1, "carriage return without linefeed");
						break;
					}
					if (nread != sizeof(close))
						close[nread++] = ch;
				}

				if (nread != sizeof(close)) {
					close[nread] = '\0';
					connection_close = !strcasecmp(close, "close");
				}
			}
			else if (!strcasecmp(header_name, "content-length")) {
				const char *errstr;
				char number[19 /* log10(2^63-1) + 1 (rounded down) */];

				nread = 0;
				socket_skip_space(sock, tls);
				for (;;) {
					int ch;

					ch = socket_getc(sock, tls);
					if (ch == '\r') {
						if (socket_getc(sock, tls) != '\n')
							fatalx(1, "carriage return without linefeed");
						break;
					}
					if (!isdigit(ch))
						fatalx(1, "invalid Content-Length");
					if (nread == sizeof(number) - 1)
						fatalx(1, "Content-Length was too large");
					number[nread++] = ch;
				}

				number[nread] = '\0';

				content_length = strtonum(number, 0, LLONG_MAX, &errstr);
				if (errstr != NULL)
					fatalx(1, "Content-Length was %s", errstr);
			}
			else if (!strcasecmp(header_name, "transfer-encoding")) {
				char encoding[8];

				nread = 0;
				socket_skip_space(sock, tls);
				for (;;) {
					int ch;

					ch = socket_getc(sock, tls);
					if (ch == '\r') {
						if (socket_getc(sock, tls) != '\n')
							fatalx(1, "carriage return without linefeed");
						break;
					}
					if (nread == sizeof(encoding))
						fatalx(1, "unknown Transfer-Encoding");
					encoding[nread++] = ch;
				}

				if (nread == sizeof(encoding))
					fatalx(1, "unknown Transfer-Encoding");
				encoding[nread] = '\0';

				if (strcasecmp(encoding, "chunked") != 0)
					fatalx(1, "unknown Trasnfer-Encoding");
				chunked = 1;
			}
			else {
				for (;;) {
					if (socket_getc(sock, tls) == '\r')
						if (socket_getc(sock, tls) == '\n')
							break;
				}
			}
		}
		done_headers:

		if (imsg_compose(&msgbuf, ENGINE_IMSG_LENGTH, 0, -1, -1,
				 &content_length, sizeof(content_length)) == -1)
			fatal(1, "imsg_compose");
		if (imsgbuf_flush(&msgbuf) == -1)
			fatal(1, "imsgbuf_flush");

		if (chunked) {
			long long last_update;

			total_read = 0;
			last_update = 0;
			for (;;) {
				size_t nread;
				unsigned long long size;
				int ch, gotnum;
				char number[16 /* log16(2^63-1) + 1 (rounded down) */];

				gotnum = 0;
				nread = 0;
				for (;;) {
					ch = socket_getc(sock, tls);
					if (!gotnum) {
						if (ch == '\r' || ch == ' ') {
							char *ep;

							number[nread] = '\0';
							size = strtoull(number, &ep, 16);
							if (number[0] == '\0' || *ep != '\0')
								fatalx(1, "chunk size was invalid");
							if (size == ULLONG_MAX && errno == ERANGE)
								fatalx(1, "chunk size was too large");
							gotnum = 1;
						}
						else if (!isxdigit(ch))
							fatalx(1, "invalid chunk size");
						else {
							if (nread == sizeof(number) - 1)
								fatalx(1, "chunk size too large");
							number[nread++] = ch;
						}
					}

					if (ch == '\r') {
						if (socket_getc(sock, tls) != '\n')
							fatalx(1, "carriage return without line feed");
						break;
					}
				}

				if (size == 0)
					break; /* ignore trailer */

				total_read += size;
				while (size != 0) {
					size_t toread;

					toread = min(sizeof(buf), size);
					socket_read_all(sock, tls, buf, toread);

					if (fwrite(buf, 1, toread, output_file) != toread)
						fatal(1, "fwrite");
					size -= toread;
				}

				if (socket_getc(sock, tls) != '\r' || socket_getc(sock, tls) != '\n')
					fatalx(1, "chunk body missing CRLF");

				if (total_read - last_update > 4096) {
					if (imsg_compose(&msgbuf, ENGINE_IMSG_PROGRESS,
							 0, -1, -1, &total_read,
							 sizeof(total_read)) == -1)
						fatal(1, "imsg_compose");
					if (imsgbuf_flush(&msgbuf) == -1)
						fatal(1, "imsgbuf_flush");
					last_update = total_read;
				}
			}
		}
		else if (content_length != -1) {
			long long last_update;

			last_update = 0;
			for (total_read = 0; total_read < content_length;) {
				size_t toread;

				toread = min((long long)sizeof(buf), content_length - total_read);
				socket_read_all(sock, tls, buf, toread);

				if (fwrite(buf, 1, toread, output_file) != toread)
					fatal(1, "fwrite");
				total_read += toread;

				if (total_read - last_update > 4096) {
					if (imsg_compose(&msgbuf, ENGINE_IMSG_PROGRESS,
							 0, -1, -1, &total_read,
							 sizeof(total_read)) == -1)
						fatal(1, "imsg_compose");
					if (imsgbuf_flush(&msgbuf) == -1)
						fatal(1, "imsgbuf_flush");
					last_update = total_read;
				}
			}
		}
		else if (connection_close) {
			long long last_update;

			last_update = 0;
			total_read = 0;
			for (;;) {
				ssize_t nread;

				nread = socket_read(sock, tls, buf, sizeof(buf));
				if (nread == 0)
					break;

				if (fwrite(buf, 1, nread, output_file) != (size_t)nread)
					fatal(1, "fwrite");
				total_read += nread;

				if (total_read - last_update > 4096) {
					if (imsg_compose(&msgbuf, ENGINE_IMSG_PROGRESS,
							 0, -1, -1,
							 &total_read,
							 sizeof(total_read)) == -1)
						fatal(1, "imsg_compose");
					if (imsgbuf_flush(&msgbuf) == -1)
						fatal(1, "imsgbuf_flush");
					last_update = total_read;
				}
			}
		}
		else
			fatalx(1, "no content framing specified");

		if (imsg_compose(&msgbuf, ENGINE_IMSG_DOWNLOAD_OVER, 0,
				 -1, -1, &total_read,
				 sizeof(total_read)) == -1)
			fatal(1, "imsg_compose");
		if (imsgbuf_flush(&msgbuf) == -1)
			fatal(1, "imsgbuf_flush");

		if (output_file != stdout)
			fclose(output_file);
		if (tls != NULL) {
			tls_close(tls);
			tls_free(tls);
		}
		close(sock);
	}

	if (output_file_orig != NULL && output_file_orig != stdout)
		fclose(output_file_orig);
	tls_config_free(tls_config);
	imsgbuf_clear(&msgbuf);
	close(3);
}
