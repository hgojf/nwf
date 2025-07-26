#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <imsg.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <util.h>

#include "engine.h"
#include "imsg-blocking.h"
#include "pathnames.h"

static void
engine_errx(int ex, struct imsg *msg)
{
	size_t i;
	char buf[ENGINE_ERROR_MAX];

	if (imsg_get_data(msg, buf, sizeof(buf)) == -1)
		errx(1, "engine sent data with wrong size");
	if (memchr(buf, '\0', sizeof(buf)) == NULL)
		errx(1, "engine sent string without null terminator");
	for (i = 0; buf[i] != '\0'; i++)
		if (!isprint(buf[i]) && !isspace(buf[i]))
			errx(1, "engine sent error message with nonprinting characters");

	fprintf(stderr, "nwf-engine: %s\n", buf);
	exit(ex);
}

static void
usage(void)
{
	fprintf(stderr, "usage: nwf [-o file] [url ...]\n");
	exit(2);
}

int
main(int argc, char *argv[])
{
	struct imsgbuf msgbuf;
	const char *engine_path, *output_path;
	int ch, dev_null, i, need_path, output_stdout, sv[2];

	/*
	 * Cant use getprogname(3) because it will remove the "./"
	 */
	if (!strcmp(argv[0], "./nwf"))
		engine_path = "./nwf-engine";
	else
		engine_path = PATH_NWF_ENGINE;

	output_path = NULL;
	while ((ch = getopt(argc, argv, "o:")) != -1) {
		switch (ch) {
		case 'o':
			output_path = optarg;
			break;
		default:
			usage();
		}
	}

	argc -= optind;
	argv += optind;

	if (argc == 0)
		usage();

	output_stdout = (output_path != NULL && !strcmp(output_path, "-"));

	if ((dev_null = open(PATH_DEV_NULL, O_RDWR | O_CLOEXEC)) == -1)
		err(1, "%s", PATH_DEV_NULL);

	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, PF_UNSPEC, sv) == -1)
		err(1, "socketpair");
	if (imsgbuf_init(&msgbuf, sv[0]) == -1)
		err(1, "imsgbuf_init");
	imsgbuf_allow_fdpass(&msgbuf);
	switch (fork()) {
	case -1:
		err(1, "fork");
	case 0:
		/*
		 * It is okay to call err(3) here (which calls exit(3)),
		 * because we have not written to a stdio file and are
		 * not using atexit(3) handlers.
		 */
		for (i = 0; i < 3; i++) {
			if (i == STDOUT_FILENO && output_stdout)
				continue;
			if (dup2(dev_null, i) == -1)
				err(1, "dup2");
		}
		if (dup2(sv[1], 3) == -1)
			err(1, "dup2");
		execl(engine_path, "nwf-engine", "-r", NULL);
		err(1, "%s", PATH_NWF_ENGINE);
	default:
		break;
	}
	close(dev_null);
	close(sv[1]);

	signal(SIGPIPE, SIG_IGN);

	if (output_path == NULL) {
		if (unveil(".", "cw") == -1)
			err(1, ".");
		if (pledge("stdio cpath wpath sendfd", NULL) == -1)
			err(1, "pledge");
		if (imsg_compose(&msgbuf, ENGINE_IMSG_NEED_PATH, 0, -1, -1,
				 NULL, 0) == -1)
			err(1, "imsg_compose");
		if (imsgbuf_flush(&msgbuf) == -1)
			err(1, "imsgbuf_flush");
		need_path = 1;

	}
	else {
		char *trailing_slash;

		if (argc > 1)
			errx(1, "cannot specify -o with multiple urls");

		if ((trailing_slash = strrchr(output_path, '/')) != NULL
		    && trailing_slash[1] == '\0')
			*trailing_slash = '\0';

		if (output_stdout) {
			if (pledge("stdio", NULL) == -1)
				err(1, "pledge");
			if (imsg_compose(&msgbuf, ENGINE_IMSG_FILE_STDOUT, 0, -1,
					 -1, NULL, 0) == -1)
				err(1, "imsg_compose");
			if (imsgbuf_flush(&msgbuf) == -1)
				err(1, "imsgbuf_flush");
		}
		else {
			int output_file;

			output_file = open(output_path,
					   O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
					   0644);
			if (output_file == -1)
				err(1, "%s", output_path);

			if (imsg_compose(&msgbuf, ENGINE_IMSG_FILE, 0, -1,
					 output_file, NULL, 0) == -1)
				err(1, "imsg_compose");
			if (imsgbuf_flush(&msgbuf) == -1)
				err(1, "imsgbuf_flush");
			if (pledge("stdio", NULL) == -1)
				err(1, "pledge");
		}

		need_path = 0;
	}

	for (; *argv != NULL; argv++) {
		struct imsg msg;
		int got_progress, n;
		char url[ENGINE_URL_MAX];

		memset(url, 0, sizeof(url));
		if (strlcpy(url, *argv, sizeof(url))
			    >= sizeof(url))
			errx(1, "url '%s' too long", *argv);

		if (imsg_compose(&msgbuf, ENGINE_IMSG_DOWNLOAD, 0, -1, -1,
				 url, sizeof(url)) == -1)
			err(1, "imsg_compose");
		if (imsgbuf_flush(&msgbuf) == -1)
			err(1, "imsgbuf_flush");

		for (;;) {
			char url[ENGINE_URL_MAX];

			n = imsg_get_blocking(&msgbuf, &msg);
			if (n == -1)
				err(1, "imsg_get_blocking");
			if (n == 0)
				errx(1, "imsg_get_blocking EOF");
			if (imsg_get_type(&msg) == ENGINE_IMSG_ERROR)
				engine_errx(1, &msg);

			if (imsg_get_type(&msg) == ENGINE_IMSG_PATH)
				break;
			if (imsg_get_type(&msg) == ENGINE_IMSG_REDIRECT_OVER)
				break;

			if (imsg_get_type(&msg) != ENGINE_IMSG_REDIRECT)
				errx(1, "engine sent unknown imsg type");

			if (imsg_get_data(&msg, url, sizeof(url)) == -1)
				errx(1, "client sent data with wrong size");
			if (memchr(url, '\0', sizeof(url)) == NULL)
				errx(1, "client sent string without null terminator");
			fprintf(stderr, "Redirected to %s\n", url);

			imsg_free(&msg);
		}

		/*
		 * We got an imsg from the loop.
		 */
		if (imsg_get_type(&msg) == ENGINE_IMSG_PATH) {
			size_t i;
			char *dotdot, path[PATH_MAX];
			int output_file_send;

			if (!need_path)
				errx(1, "engine sent path when it was not needed");
			if (imsg_get_data(&msg, path, sizeof(path)) == -1)
				errx(1, "engine sent data with wrong size");
			if (memchr(path, '\0', sizeof(path)) == NULL)
				errx(1, "engine sent string without null terminator");
			if (path[0] == '/')
				errx(1, "engine sent absolute path");
			dotdot = path;
			while ((dotdot = strstr(dotdot, "..")) != NULL) {
				if (dotdot[2] == '/' || dotdot[2] == '\0')
					errx(1, "engine sent relative path");
				dotdot += 3;
			}
			if (strchr(path, '/') != NULL)
				errx(1, "engine sent filename with path separator");
			for (i = 0; path[i] != '\0'; i++)
				if (!isprint(path[i]) && !isspace(path[i]))
					errx(1, "engine sent path with nonprinting characters");

			if ((output_file_send = open(path,
						  O_WRONLY | O_CREAT | O_EXCL | O_TRUNC,
						  0644)) == -1) {
				if (errno == EEXIST) {
					int ch;

					fprintf(stderr, "file %s exists, overwrite? (y/n) ", path);

					ch = fgetc(stdin);
					switch (ch) {
					case 'n':
						if ((ch = fgetc(stdin)) != EOF && ch != '\n')
							errx(1, "invalid response");
						errx(1, "not saving file");
					case 'y':
						if ((ch = fgetc(stdin)) != EOF && ch != '\n')
							errx(1, "invalid response");
						break;
					default:
						errx(1, "invalid response");
					}

					output_file_send = open(path,
								 O_WRONLY | O_CREAT | O_TRUNC,
								 0644);
					if (output_file_send == -1)
						err(1, "%s", path);
				}
				err(1, "%s", path);
			}

			if (imsg_compose(&msgbuf, ENGINE_IMSG_FILE, 0,
					 -1, output_file_send, NULL, 0) == -1)
				err(1, "imsg_compose");
			if (imsgbuf_flush(&msgbuf) == -1)
				err(1, "imsgbuf_flush");

			fprintf(stderr, "saving file to %s\n", path);
		}
		else {
			if (need_path)
				errx(1, "engine didnt send path when it was needed");
			if (output_stdout)
				fprintf(stderr, "saving file to stdout\n");
			else
				fprintf(stderr, "saving file to %s\n", output_path);
		}

		imsg_free(&msg);

		got_progress = 0;
		for (;;) {
			struct engine_progress progress;
			char content_length[FMT_SCALED_STRSIZE];
			char total_read[FMT_SCALED_STRSIZE];

			n = imsg_get_blocking(&msgbuf, &msg);
			if (n == -1)
				err(1, "imsg_get_blocking");
			if (n == 0)
				errx(1, "imsg_get_blocking EOF");

			if (imsg_get_type(&msg) == ENGINE_IMSG_ERROR)
				engine_errx(1, &msg);
			if (imsg_get_type(&msg) == ENGINE_IMSG_DOWNLOAD_OVER) {
				imsg_free(&msg);
				break;
			}

			if (imsg_get_type(&msg) != ENGINE_IMSG_PROGRESS)
				errx(1, "engine sent unknown imsg type");
			if (imsg_get_data(&msg, &progress, sizeof(progress)) == -1)
				errx(1, "engine sent data with wrong size");
			if (progress.percent > 100)
				errx(1, "engine sent percentage greater than 100%%");
			if (fmt_scaled(progress.content_length, content_length) == -1)
				err(1, "fmt_scaled");
			if (fmt_scaled(progress.total_read, total_read) == -1)
				err(1, "fmt_scaled");
			fprintf(stderr, "\x1b[K%d%% (%s/%s)\r",
				progress.percent, total_read, content_length);
			got_progress = 1;

			imsg_free(&msg);
		}

		if (got_progress)
			fprintf(stderr, "\n");
	}

	imsgbuf_clear(&msgbuf);
	close(sv[0]);
}
