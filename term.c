/*
 * JFBTERM -
 * Copyright (c) 2003 Fumitoshi UKAI <ukai@debian.or.jp>
 * Copyright (C) 1999  Noritoshi MASUICHI (nmasu@ma3.justnet.ne.jp)
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY NORITOSHI MASUICHI ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL NORITOSHI MASUICHI BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <dlfcn.h>
#include <time.h>
#include <sys/types.h>
#include <sys/kd.h>
#include <ctype.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <pwd.h>
#include <pty.h>
#include <utmp.h>
#include <grp.h>
#include <stdarg.h>

#include "term.h"
#include "vterm.h"
#include "fbcommon.h"
#include "font.h"
#include "message.h"
#include "main.h"
#include "util.h"

#include "config.h"

#if 1 // Hangul
#include "automata.h"
#include "comp.h"
#endif

int gChildProcessId = 0;

TTerm gTerm;

void tterm_wakeup_shell(TTerm* p, const char* tn);
void tterm_final(TTerm* p);

static void tterm_set_utmp(TTerm* p);
static void tterm_reset_utmp(TTerm* p);

void send_hangup(
	int closure)
{
	if (gChildProcessId) {
		kill(gChildProcessId, SIGHUP);
	}
}

void sigchld(sig) int sig; {
	int st;
	int ret;
	ret = wait(&st);
	if (ret == gChildProcessId || ret == ECHILD) {
		tvterm_unregister_signal();
		tterm_final(&gTerm);
		exit(EXIT_SUCCESS);
	}
	signal(SIGCHLD, sigchld);
}


void tterm_init(TTerm* p, const char* en)
{
	p->ptyfd = -1;
	p->ttyfd = -1;
	p->name[0] = '\0';
	tcgetattr(0, &(p->ttysave));
	tvterm_init(&(p->vterm), p,
		    gFramebuffer.width/gFontsWidth,
		    gFramebuffer.height/gFontsHeight, 
		    &(gApp.gCaps), en);
}

void tterm_final(TTerm* p)
{
	tterm_reset_utmp(p);
	tvterm_final(&(p->vterm));
}

void application_final(void)
{
	TTerm* p = &gTerm;
/*
	write(1, "\x1B[?25h", 6);
*/
	tcsetattr(0, TCSAFLUSH, &(p->ttysave));
	tterm_final(p);

	tfbm_close(&gFramebuffer);
	tfont_ary_final();
}
	
int tterm_get_ptytty(TTerm* p)
{
	if (openpty(&p->ptyfd, &p->ttyfd, p->name, NULL, NULL) < 0) {
	    print_strerror("openpty");
	    return 0;
	}
	return 1;
}

#if 1 // Hangul
int get_shift_state(void)
{
	int na = 6, ns = 0;
	if(ioctl(fileno(stdin), TIOCLINUX, &na) == 0) ns = na;
	return ns;
}

int get_capslock_state(void)
{
	long int na = 0;

	if(ioctl(fileno(stdin), KDGKBLED, &na) == -1){
        return 0;
    }

    if(na >= 4){
        return 1;
    }

	return 0;
}

int get_toggle_state(void)
{
    // i want use capslock
    return get_capslock_state();
    // i want use shift
    //return get_shift_state();
}

int reverse_uplower_character(u_char ch_input, u_char *ch_output)
{
    int ret = 0;

    // disable capslock effect
    // LED  == ON && Character == Alphabet
    if(isalpha((unsigned int)ch_input) != 0){
        if(isupper((int)ch_input) != 0){
            // Upppercase   => Lowercase
            *ch_output = ch_input + 0x20;
            ret             = 1;
        }else{
            // Lowercase    => Uppercase
            *ch_output = ch_input - 0x20;
            ret             = 2;
        }
    }

    return ret;
}

void convert_character(int hangul_state, u_char ch_input, u_char *ch_output)
{  
    int print_type;

    // korean  -> capslock on  -> convert (lower <-> upper)
    // english -> capslock off -> literally (...)
    if(hangul_state == 1){
        print_type = reverse_uplower_character(ch_input, ch_output);
    }else{
        print_type = 0;
    }

    if(print_type == 0){
        *ch_output = ch_input;
    }
}

void debug_printf(TVterm* ttyfd, const char *fmt, ...)
{
    unsigned char buffer[1024] = {0};
    int string_length = 0;
    va_list arg;

    va_start(arg, fmt);

    // warning ! overflow!
    vsprintf(buffer, fmt, arg);
    string_length = strlen(buffer);

    tvterm_emulate(ttyfd, buffer, string_length);
}
#endif

#define BUF_SIZE 1024
void tterm_start(TTerm* p, const char* tn, const char* en)
{
	struct termios ntio;

	int ret;
	struct timeval tv;
	u_char read_buf[BUF_SIZE+1];
#if 1 // Hangul
	extern int hangul_state;
	extern int hangul_output_code;  // UTF-8 ?
	extern int process_hangul_input;
	u_char constr[BUF_SIZE+1],
           han_last_char[BUF_SIZE+1] = {0},
           capslock_convert_character;
	int i, show_fig, hconstr = 0;
    int togglekey_status_old    = 0,
        togglekey_status        = 0;
#endif
#ifdef JFB_ENABLE_DIMMER
	u_int idle_time = 0;
	u_int blank = 0;
	int tfbm_set_blank(int, int);
#  define DIMMER_TIMEOUT (3 * 60 * 10)        /* 3 min */
#endif

	tterm_init(p, en);
	if (!tterm_get_ptytty(p)) {
		die("Cannot get free pty-tty.\n");
	}

	ntio                = p->ttysave;
	ntio.c_lflag       &= ~(ECHO|ISIG|ICANON|XCASE);
    ntio.c_iflag        = 0;
    ntio.c_oflag       &= ~OPOST;
    ntio.c_cc[VMIN]     = 1;
    ntio.c_cc[VTIME]    = 0;
	ntio.c_cflag       |= CS8;
    ntio.c_line         = 0;
	tcsetattr(0, TCSAFLUSH, &ntio);

    /* write(1, "\x1B[?25l", 6); */

	tvterm_start(&(p->vterm));
	fflush(stdout);

	gChildProcessId = fork();
	if (gChildProcessId == 0) {
	    /* child */
	    tterm_wakeup_shell(p, tn);
	    exit(1);
	} else if (gChildProcessId < 0) {
	    print_strerror("fork");
	    exit(1);
	}

	/* parent */
	tterm_set_utmp(p);
	signal(SIGCHLD, sigchld);
	atexit(application_final);

	/* not available
	 * VtInit();
	 * VtStart();
	 */
	for (;;) {
		fd_set fds;
		int max = 0;
		tv.tv_sec = 0;
		tv.tv_usec = 100000;	// 100 msec
		FD_ZERO(&fds);
		FD_SET(0,&fds);
		FD_SET(p->ptyfd,&fds);

		if (p->ptyfd > max) {
            max = p->ptyfd;
        }

		ret = select(max+1, &fds, NULL, NULL, &tv);

        if (ret == 0 || (ret < 0 && errno == EINTR)) {
#ifdef JFB_ENABLE_DIMMER
			if (!blank && ++idle_time > DIMMER_TIMEOUT) {
				// Goto blank
				idle_time = 0;
				if (tfbm_set_blank(gFramebuffer.fh, 1))
					blank = 1;
			}
#endif
			continue;
		}

		if (ret < 0) {
			print_strerror_and_exit("select");
		}

		if (FD_ISSET(0, &fds)) {
            ret = read(0, read_buf, BUF_SIZE);
            
#ifdef JFB_ENABLE_DIMMER
			idle_time = 0;

			if (blank) {
				// Wakeup console
				blank = 0;
				tfbm_set_blank(gFramebuffer.fh, 0);
			}
#endif
			if (ret > 0) {
#if 1 // Hangul
                if (process_hangul_input) {
                    togglekey_status_old  = togglekey_status;
		            togglekey_status      = get_toggle_state();

                    // status change
                    if (togglekey_status_old != togglekey_status) {
                        get_ime_status(han_last_char);
                        // changed process buf string
                        // if not use hangul_automata_clear()...
                        // ENG -> HAN fix    read_buf: A -> A
                        // HAN -> END modify read_buf: A -> (MIOUM)
                        hangul_automata_clear();
                        hangul_automata_toggle(read_buf);
                        //debug_printf(&(p->vterm), "Cst:\"%s\"\"%s\"\n", read_buf, han_last_char);
                    }

	                for (i = 0; i < ret; i++) {
                        // if you want change character... (must be use capslock toggle key!)
                        convert_character(togglekey_status, read_buf[i], &capslock_convert_character);
                        // if combine, print two character (not full)
                        show_fig = hangul_automata(capslock_convert_character, read_buf);
                        //debug_printf(&(p->vterm), "(%d)-'%c' '%d' \"%s\"", ret, capslock_convert_character, show_fig, read_buf);
                        switch (show_fig) {
                            // korean in cursor (print combine processing)
                            // -> process buf : alphabet
                            case 0:
                                // get curser korean jamo
                                get_ime_status(constr);
                                //debug_printf(&(p->vterm), "Johap: '%s' '%d'\n", constr, constr[0]);
                                // only event - selected (print combine process) + press backspace
                                // now position character change, no move
                                if (constr[0] == 0) { // bkspc: clear composing
                                    memset(constr, ' ', 2);
                                    tvterm_emulate(&(p->vterm), constr, 2);
                                } else if (hangul_output_code == 0){
                                    tvterm_emulate(&(p->vterm), constr, 3);
                                } else {
                                    tvterm_emulate(&(p->vterm), constr, 2);
                                }

                                p->vterm.pen.x -= 2;
                                tvterm_refresh(&(p->vterm));
                                break;
                            // print ascsii character
                            case 1:
                                // flush korean
                                if(strcmp(han_last_char, "") != 0){
                                    if(hangul_output_code == 0) {
                                        write(p->ptyfd, han_last_char, 3);
                                    } else {
                                        write(p->ptyfd, han_last_char, 2);
                                    }
                                    memset(han_last_char, 0, sizeof(han_last_char));
                                }
                                //debug_printf(&(p->vterm), "ASCII:'%s'\n", han_last_char);
                                write(p->ptyfd, read_buf, show_fig);
                                break;
                            // korean character is full! unable insert more JAMO
                            // -> read_buf: save hangul (!! Not certain character!, able change!)
                            default:
                                //debug_printf(&(p->vterm), "FL:'%s'\n", read_Buf);
			                    if(hangul_output_code == 0) {
				                    write(p->ptyfd, read_buf, show_fig + 1);
                                } else {
				                    write(p->ptyfd, read_buf, show_fig);
                                }
			
                                get_ime_status(constr);
                                if (constr[0] != 0) {
                                    hconstr = 1;
                                }
                                break;
		                    }
	                    }
                } else {
	                write(p->ptyfd, read_buf, ret);
                }
#else
				write(p->ptyfd, read_buf, ret);
#endif
			}
		} else if(FD_ISSET(p->ptyfd,&fds)) {
			ret = read(p->ptyfd, read_buf, BUF_SIZE);
			if (ret > 0) {
				// write(1, read_buf, ret);
				tvterm_emulate(&(p->vterm), read_buf, ret);
				tvterm_refresh(&(p->vterm));
#if 1 // Hangul - cursor out of character, print one FULL character, next forward
      //          (if not use this section, last character is cut)
                if (process_hangul_input) {
	                if (hconstr) {
		                if (hangul_output_code == 0) {
			                tvterm_emulate(&(p->vterm), constr, 3);
                        } else {
			                tvterm_emulate(&(p->vterm), constr, 2);
                        }
		
                        p->vterm.pen.x -= 2;
                        tvterm_refresh(&(p->vterm));
		                hconstr = 0;
	                }
                }
#endif
			}
		}
	}
}

void tterm_wakeup_shell(TTerm* p, const char* tn)
{
	setenv("TERM", tn, 1);
	close(p->ptyfd);
	login_tty(p->ttyfd);
	tcsetattr(0, TCSANOW, &(p->ttysave));
	setgid(getgid());
	setuid(getuid());
	sleep(1); /* XXX: wait vt swtich completed? */
	execvp(gApp.gExecShell, gApp.gExecShellArgv);
	exit(1);
}


void	tterm_set_utmp(TTerm* p)
{
	struct utmp	utmp;
	struct passwd	*pw;
	char	*tn;

	pw = getpwuid(util_getuid());
	tn = rindex(p->name, '/') + 1;
	memset((char *)&utmp, 0, sizeof(utmp));
	strncpy(utmp.ut_id, tn + 3, sizeof(utmp.ut_id));
	utmp.ut_type = DEAD_PROCESS;
	setutent();
	getutid(&utmp);
	utmp.ut_type = USER_PROCESS;
	utmp.ut_pid = getpid();
	if (strncmp("/dev/", p->name, 5) == 0)
	    tn = p->name + 5;
	strncpy(utmp.ut_line, tn, sizeof(utmp.ut_line));
	strncpy(utmp.ut_user, pw->pw_name, sizeof(utmp.ut_user));
	time(&(utmp.ut_time));
	pututline(&utmp);
	endutent();
}

void	tterm_reset_utmp(TTerm* p)
{
	struct utmp	utmp, *utp;
	char	*tn;

	tn = rindex(p->name, '/') + 4;
	memset((char *)&utmp, 0, sizeof(utmp));
	strncpy(utmp.ut_id, tn, sizeof(utmp.ut_id));
	utmp.ut_type = USER_PROCESS;
	setutent();
	utp = getutid(&utmp);
	utp->ut_type = DEAD_PROCESS;
	memset(utp->ut_user, 0, sizeof(utmp.ut_user));
	utp->ut_type = DEAD_PROCESS;
	time(&(utp->ut_time));
	pututline(utp);
	endutent();
}
