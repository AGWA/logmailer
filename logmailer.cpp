/*
 * Copyright (C) 2014 Andrew Ayer
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 * Except as contained in this notice, the name(s) of the above copyright
 * holders shall not be used in advertising or otherwise to promote the
 * sale, use or other dealings in this Software without prior written
 * authorization.
 */

#include <iostream>
#include <fstream>
#include <sstream>
#include <signal.h>
#include <sys/select.h>
#include <sys/wait.h>
#include <cstring>
#include <cstddef>
#include <string>
#include <ctime>
#include <cstdlib>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#include <sys/types.h>

static void print_usage (const char* argv0, std::ostream& out =std::clog)
{
	out << "Usage: " << argv0 << " [-f] [-u user] [-g group] [-p pidfile] [-m min_wait_time] [-M max_wait_time] [-r recipient] [-s subject] fifo_path" << std::endl;
}

sig_atomic_t		is_running = 1;
std::string		hostname;

struct System_error {
	std::string	syscall;
	std::string	target;
	int		number;

	System_error (const std::string& arg_syscall, const std::string& arg_target, int arg_number)
	: syscall(arg_syscall), target(arg_target), number(arg_number) { }
};

static std::string get_hostname ()
{
#ifndef HOST_NAME_MAX
#define HOST_NAME_MAX 255
#endif
	char	buffer[HOST_NAME_MAX + 1];
	buffer[HOST_NAME_MAX] = '\0';
	if (gethostname(buffer, HOST_NAME_MAX) == -1) {
		throw System_error("gethostname", "", errno);
	}
	return buffer;
}

static void graceful_termination_handler (int)
{
	is_running = 0;
}

static void init_signals ()
{
	struct sigaction		siginfo;

	sigemptyset(&siginfo.sa_mask);
	sigaddset(&siginfo.sa_mask, SIGINT);
	sigaddset(&siginfo.sa_mask, SIGTERM);

	// SIGINT and SIGTERM
	siginfo.sa_flags = 0;
	siginfo.sa_handler = graceful_termination_handler;
	sigaction(SIGINT, &siginfo, NULL);
	sigaction(SIGTERM, &siginfo, NULL);

	// SIGPIPE
	siginfo.sa_flags = 0;
	siginfo.sa_handler = SIG_IGN;
	sigaction(SIGPIPE, &siginfo, NULL);

	// Block SIGINT, SIGTERM, SIGCHLD; they will be unblocked
	// at a convenient time
	sigprocmask(SIG_BLOCK, &siginfo.sa_mask, NULL);
}

static void set_nonblocking (int fd, bool nonblocking)
{
	int		old_flags = fcntl(fd, F_GETFL);
	if (old_flags == -1) {
		throw System_error("fcntl(F_GETFL)", "", errno);
	}
	int		new_flags = old_flags;
	if (nonblocking) {
		new_flags |= O_NONBLOCK;
	} else {
		new_flags &= ~O_NONBLOCK;
	}
	if (new_flags != old_flags && fcntl(fd, F_SETFL, new_flags) == -1) {
		throw System_error("fcntl(F_SETFL)", "", errno);
	}
}

static void drop_privileges (const char* username, const char* groupname)
{
	if (!username && !groupname) {
		return;
	}

	struct passwd*		usr = NULL;
	struct group*		grp = NULL;
	if (username) {
		errno = 0;
		if (!(usr = getpwnam(username))) {
			throw System_error("getpwnam", username, errno ? errno : ENOENT);
		}
	}

	if (groupname) {
		errno = 0;
		if (!(grp = getgrnam(groupname))) {
			throw System_error("getgrnam", groupname, errno ? errno : ENOENT);
		}
	}

	// If no group is specified, but a user is specified, drop to the primary GID of that user
	if (setgid(grp ? grp->gr_gid : usr->pw_gid) == -1) {
		throw System_error("setgid", "", errno);
	}

	if (usr) {
		if (initgroups(usr->pw_name, usr->pw_gid) == -1) {
			throw System_error("initgroups", usr->pw_name, errno);
		}
		if (setuid(usr->pw_uid) == -1) {
			throw System_error("setuid", usr->pw_name, errno);
		}
	}
}

static void daemonize (const char* pid_file)
{
	// Open the PID file (open before forking so we can report errors)
	std::ofstream	pid_out;
	if (pid_file) {
		pid_out.open(pid_file, std::ofstream::out | std::ofstream::trunc);
		if (!pid_out) {
			throw System_error("open", pid_file, errno);
		}
	}

	// Fork
	pid_t		pid = fork();
	if (pid == -1) {
		throw System_error("fork", "", errno);
	}
	if (pid != 0) {
		// Exit parent
		_exit(0);
	}
	setsid();

	// Write the PID file now that we've forked
	if (pid_out) {
		pid_out << getpid() << '\n';
		pid_out.close();
	}

	// dup FDs to /dev/null
	close(0);
	close(1);
	close(2);
	open("/dev/null", O_RDONLY);
	open("/dev/null", O_WRONLY);
	open("/dev/null", O_WRONLY);
}

static std::size_t count_newlines (const char* p, std::size_t len)
{
	std::size_t cnt = 0;
	while (len--) {
		if (*p++ == '\n') {
			++cnt;
		}
	}
	return cnt;
}

static void send_mail (const std::string& to, const std::string& subject, const char* body, std::size_t body_len)
{
	int			pipefd[2];
	if (pipe(pipefd) == -1) {
		throw System_error("pipe", "", errno);
	}
	pid_t			sendmail_pid = fork();
	if (sendmail_pid == -1) {
		// TODO: don't leak pipefd (not that it really matters)
		throw System_error("fork", "", errno);
	}
	if (sendmail_pid == 0) {
		close(pipefd[1]);
		if (pipefd[0] != 0) {
			dup2(pipefd[0], 0);
			close(pipefd[0]);
		}
		execlp("sendmail", "sendmail", "-i", to.c_str(), (char*)NULL);
		perror("sendmail");
		_exit(-1);
	}

	close(pipefd[0]);

	FILE*			sendmail_out = fdopen(pipefd[1], "w");
	if (!sendmail_out) {
		// TODO: don't leak pipefd, still wait for child (not that it really matters)
		throw System_error("fdopen", "", errno);
	}

	fprintf(sendmail_out, "To: %s\n", to.c_str());
	fprintf(sendmail_out, "Subject: %s\n", subject.c_str());
	fputs("\n", sendmail_out);
	fwrite(body, 1, body_len, sendmail_out);
	fclose(sendmail_out);

	waitpid(sendmail_pid, NULL, 0);
	// We can't really do anything if sending mail fails... trying to log to syslog is
	// kinda pointless and could even result in a feedback loop.
}


class Log_mailer {
public:
	int			fd;
	std::string		recipient;
	std::string		subject_format;
	std::time_t		min_wait_time;
	std::time_t		max_wait_time;
	std::string::size_type	max_buffer_size;

private:
	enum {
		default_min_wait_time = 5,
		default_max_wait_time = 60,
		default_max_buffer_size = 65536
	};

	std::string		buffer;
	std::string::size_type	last_newline;
	std::time_t		start_time;	// only valid if last_newline != std::string::npos

	bool			has_complete_message () const { return last_newline != std::string::npos; }

	void flush ()
	{
		if (!has_complete_message()) {
			return;
		}


		const char* const	message = buffer.data();
		const std::size_t	message_len = last_newline + 1;
		send_mail(recipient, format_subject(message, message_len), message, message_len);

		buffer.erase(0, last_newline + 1);
		last_newline = std::string::npos;
	}

public:
	Log_mailer ()
	: fd(-1),
	  recipient("root"),
	  subject_format("Log messages from %h"),
	  min_wait_time(default_min_wait_time),
	  max_wait_time(default_max_wait_time),
	  max_buffer_size(default_max_buffer_size),
	  last_newline(std::string::npos)
	{
	}
	~Log_mailer ()
	{
		if (fd != -1) {
			close(fd);
		}
	}

	void run (const sig_atomic_t& is_running)
	{
		fd_set			rfds;
		FD_ZERO(&rfds);
		int			nfds = fd + 1;

		sigset_t		empty_sigset;
		sigemptyset(&empty_sigset);

		while (is_running) {
			FD_SET(fd, &rfds);

			struct timespec	timeout;
			if (has_complete_message()) {
				timeout.tv_sec = min_wait_time;
				timeout.tv_nsec = 0;

				std::time_t	now = std::time(NULL);

				if (now >= start_time + max_wait_time) {
					flush();
				} else if ((start_time + max_wait_time) - now < timeout.tv_sec) {
					timeout.tv_sec = (start_time + max_wait_time) - now;
				}
			}

			int		select_res = pselect(nfds, &rfds, NULL, NULL,
								has_complete_message() ? &timeout : NULL,
								&empty_sigset);
			if (select_res == -1) {
				if (errno == EINTR) {
					continue;
				}
				throw System_error("pselect", "", errno);
			}
			if (select_res == 0) {
				// implied: has_complete_message() is true because otherwise we wouldn't
				// have passed a timeout to pselect() so pselect() could not have returned 0.
				flush();
				continue;
			}

			char		read_buffer[1024];
			ssize_t		bytes_read = read(fd, read_buffer, sizeof(read_buffer));
			if (bytes_read == -1) {
				if (errno == EAGAIN) {
					continue;
				}
				throw System_error("pselect", "", errno);
			}

			if (const void* newline = std::memchr(read_buffer, '\n', bytes_read)) {
				if (!has_complete_message()) {
					start_time = std::time(NULL);
				}
				last_newline = buffer.size() + (static_cast<const char*>(newline) - read_buffer);
			}

			buffer.append(read_buffer, bytes_read);
			if (has_complete_message() && buffer.size() >= max_buffer_size) {
				flush();
			}
		}
	}

	std::string format_subject (const char* message, std::size_t message_len) const
	{
		std::ostringstream	subject;
		const char*		p = subject_format.c_str();
		while (p[0]) {
			if (p[0] == '%' && p[1] == 'h') {
				subject << hostname;
				p += 2;
			} else if (p[0] == '%' && p[1] == 'c') {
				subject << count_newlines(message, message_len);
				p += 2;
			} else if (p[0] == '%' && p[1] == '%') {
				subject << '%';
				p += 2;
			} else if (p[0] == '%' && p[1]) {
				p += 2;
			} else if (p[0] == '%') {
				++p;
			} else {
				subject << p[0];
				++p;
			}
		}
		return subject.str();
	}
};


int main (int argc, char** argv)
{
	const char*			pidfile = NULL;
	bool				pidfile_created = false;
	int				exitcode = 0;

	try {
		hostname = get_hostname();

		Log_mailer		log_mailer;
		bool			no_daemonize = false;
		const char*		username = NULL;
		const char*		groupname = NULL;

		int			flag;
		while ((flag = getopt(argc, argv, "fu:g:p:m:M:r:s:")) != -1) {
			switch (flag) {
			case 'f':
				no_daemonize = true;
				break;
			case 'u':
				username = optarg;
				break;
			case 'g':
				groupname = optarg;
				break;
			case 'p':
				pidfile = optarg;
				break;
			case 'm':
				log_mailer.min_wait_time = std::atol(optarg);
				break;
			case 'M':
				log_mailer.max_wait_time = std::atol(optarg);
				break;
			case 'r':
				log_mailer.recipient = optarg;
				break;
			case 's':
				log_mailer.subject_format = optarg;
				break;
			default:
				print_usage(argv[0]);
				return 2;
			}
		}

		if (argc - optind != 1) {
			print_usage(argv[0]);
			return 2;
		}

		if (no_daemonize && pidfile) {
			std::clog << argv[0] << ": -p (PID file) can't be specified with -f (don't daemonize)" << std::endl;
			return 2;
		}

		if ((log_mailer.fd = open(argv[optind], O_RDONLY)) == -1) {
			throw System_error("open", argv[optind], errno);
		}
		set_nonblocking(log_mailer.fd, true);

		drop_privileges(username, groupname);
		if (!no_daemonize) {
			daemonize(pidfile);
			if (pidfile) {
				pidfile_created = true;
			}
		}
		init_signals();
		log_mailer.run(is_running);

	} catch (const System_error& error) {
		std::clog << argv[0] << ": " << error.syscall;
		if (!error.target.empty()) {
			std::clog << ": " << error.target;
		}
		std::clog << ": " << std::strerror(error.number) << std::endl;
		exitcode = 3;
	}
	if (pidfile_created) {
		unlink(pidfile);
	}
	return exitcode;
}

