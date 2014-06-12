#!/usr/bin/python
#
# Copyright (c) 2013 Citrix Systems, Inc.
# 
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#

"""Daemon which periodically runs sync-client for each Synchronizer."""

import argparse
import daemon
import dbus
import errno
import fcntl
import logging
import logging.handlers
import os
import select
import signal
import subprocess
import sys
import time
import traceback

# TODO: we want to have a one to one mapping between
# sync-client-daemon and sync-client instances, since each community
# of interest (realm) will have its own synchronizer VM.
# TODO: polling interval should be set by synchroniser
# TODO: add debugging messages?
# TODO: add dbus methods to add/remove/modify sync, force poll?
# TODO: simplify code now we only have one synchroniser per syncvm

DEFAULT_INTERVAL = 600
DEFAULT_TIMEOUT = 300
GRACE_PERIOD = 10
SYNC_CLIENT = "/usr/bin/sync-client"
PID_FILE = "/var/run/sync-client-daemon.pid"
DOMSTORE_SERVICE = "com.citrix.xenclient.db"
DOMSTORE_OBJECT = "/"
DOMSTORE_INTERFACE = "com.citrix.xenclient.db"

log = None

def run(syncs, once):
    """Run syncs once if once set or until one gets terminated"""
    signal_pipe_read, signal_pipe_write = os.pipe()
    set_up_signals(signal_pipe_read, signal_pipe_write)

    log.info("starting: %d synchronizer%s", len(syncs),
             "" if len(syncs) == 1 else "s")

    while True:
        terminated = do_select(syncs, signal_pipe_read)
        now = time.time()
        for sync in syncs:
            sync.update(terminated, now)
        done = syncs and (False not in [sync.finished(now) for sync in syncs])
        empty = (syncs == []) and (terminated or once)
        if done or empty:
            break

    log.info("exiting")


def do_select(syncs, signal_pipe_read):
    """Check syncs using select, return true if we have been terminated"""
    now = time.time()
    nxt = findmin([sync.get_next_action_time(now) for sync in syncs])
    timeout = max(nxt - now, 0) if nxt is not None else None

    while True:
        try:
            readable, _, _ = select.select([signal_pipe_read], [], [], timeout)
        except select.error as exc:
            if exc.args[0] != errno.EINTR:
                raise
        else:
            break

    if signal_pipe_read in readable:
        num = ord(os.read(signal_pipe_read, 1))
        if num == signal.SIGINT:
            log.info("caught interrupt signal")
            return True
        elif num == signal.SIGTERM:
            log.info("caught termination signal")
            return True

def findmin(stuff):
    """Return the smallest item in stuff, ignoring None values, or return
    None if non found"""
    filtered = [x for x in stuff if x is not None]

    if filtered:
        return min(filtered)
    else:
        return None

def set_up_signals(signal_pipe_read, signal_pipe_write):
    flags = fcntl.fcntl(signal_pipe_write, fcntl.F_GETFL, 0)
    flags |= os.O_NONBLOCK
    fcntl.fcntl(signal_pipe_write, fcntl.F_SETFL, flags)

    def handle_signal(signal_num, stack):
        os.write(signal_pipe_write, chr(signal_num))

    for signal_num in [signal.SIGCHLD, signal.SIGINT, signal.SIGTERM]:
        signal.signal(signal_num, handle_signal)
        signal.siginterrupt(signal_num, False)


def parse_args():
    """Return an arguments object"""
    description = "Periodically runs sync-client for each Synchronizer."
    parser = argparse.ArgumentParser(description=description)

    parser.add_argument("-d", "--debug",
                        action="store_true",
                        help="output debugging messages")

    parser.add_argument("-f", "--foreground",
                        action="store_true",
                        help="foreground mode: don't detach from "
                             "terminal, log to stderr")

    parser.add_argument("-o", "--once",
                        action="store_true",
                        help="retry until each synchronizer succeeds once, "
                        "then exit")
    return parser.parse_args()


def daemon_context(foreground):
    context = daemon.DaemonContext(pidfile=PidFile(PID_FILE))
    context.files_preserve = [log.syslog.socket]

    if foreground:
        context.detach_process = False
        context.stderr = sys.stderr

    return context


class Sync(object):
    """ Represents one Synchronizer. Responsible for periodically running
        sync-client for this Synchronizer. """

    def __init__(self, config, run_once, debug):
        self.config = config
        self.run_once = run_once
        self.debug = debug
        self.daemon_terminating = False
        self.child = None
        self.start_time = None
        self.sent_sigterm_time = None
        self.succeeded = False

    def finished(self, now):
        """Is the synchronizer finished?"""
        action_fn, action_time = self._get_next_action(now)
        return action_fn is None

    def get_next_action_time(self, now):
        action_fn, action_time = self._get_next_action(now)
        return action_time

    def update(self, terminating, now):
        if terminating:
            self.daemon_terminating = terminating

        if self.child is not None and self.child.poll() is not None:
            self._child_exited(now)

        action_fn, action_time = self._get_next_action(now)

        if action_fn is not None and now >= action_time:
            action_fn(now)

    def _get_next_action(self, now):
        if self.child is None:
            if self.daemon_terminating:
                return None, None
            elif self.start_time is None:
                return self._start_child, now
            elif self.run_once and self.succeeded:
                return None, None
            else:
                return self._start_child, self.start_time + self.config.interval
        else:
            if self.sent_sigterm_time is not None:
                return self._send_sigkill, self.sent_sigterm_time + GRACE_PERIOD
            elif self.daemon_terminating:
                return self._send_sigterm, now
            else:
                return self._send_sigterm, self.start_time + self.config.timeout

    def _start_child(self, now):
        log.info("%s: starting sync-client", self.config.name)

        args = ([SYNC_CLIENT] +
                (["-d"] if self.debug else []) +
                [self.config.name])

        self.child = subprocess.Popen(args, close_fds=True)
        self.start_time = now
        self.sent_sigterm_time = None

    def _send_sigterm(self, now):
        if not self.daemon_terminating:
            log.info("%s: timed out after %d seconds",
                     self.config.name, self.config.timeout)

        log.info("%s: terminating sync-client", self.config.name)
        self.child.terminate()
        self.sent_sigterm_time = now

    def _send_sigkill(self, now):
        log.info("%s: killing sync-client", self.config.name)
        self.child.kill()
        self.child.wait()

    def _child_exited(self, now):
        code = self.child.returncode

        if code == 0:
            message = "succeeded"
        elif code > 0:
            message = "failed (exit status {0})".format(code)
        else:
            message = "failed (signal {0})".format(-code)

        log.info("%s: sync-client %s", self.config.name, message)
        self.child = None

        if code == 0:
            self.succeeded = True

class Config(object):
    """ Configuration for all Synchronizers known to the device. """

    def __init__(self, domstore):
        self.domstore = domstore
        self.syncs = []

        # Only one Synchronizer per syncvm.
        self.syncs.append(SyncConfig(domstore))

class SyncConfig(object):
    """ Configuration for one Synchronizer. """

    def __init__(self, domstore):
        self.domstore = domstore
        self.name = self._get_string("name")
        self.interval = self._get_int("interval", DEFAULT_INTERVAL)
        self.timeout = self._get_int("timeout", DEFAULT_TIMEOUT)

    def _get_string(self, key, default=None):
        value = self.domstore.read(key)
        if value != "":
            return value
        elif default is not None:
            return default
        else:
            raise ConfigError("domstore key '{0}' not set".format(key))

    def _get_int(self, key, default=None):
        try:
            return int(self._get_string(key, str(default)))
        except ValueError as e:
            raise ConfigError("domstore key '{0}' has invalid value '{1}'".
                              format(key, value))

class Domstore(object):
    def __init__(self):
        bus = dbus.SystemBus()
        db_obj = bus.get_object(DOMSTORE_SERVICE, DOMSTORE_OBJECT)
        self.db = dbus.Interface(db_obj, dbus_interface=DOMSTORE_INTERFACE)

    def list(self, key):
        return self.db.list(key)

    def read(self, key):
        return self.db.read(key)

class Error(Exception):
    """ General error. Base class for other exceptions. """

class ConfigError(Error):
    """ Configuration error. """

class PidFile(object):
    """ Context manager to create and delete the pid file. """

    def __init__(self, file_name):
        self.file_name = file_name

    def __enter__(self):
        self.file = open(self.file_name, "a")
        try:
            fcntl.flock(self.file, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except IOError as e:
            if e.errno in [errno.EACCES, errno.EAGAIN]:
                raise Error("another instance is already running; "
                            "file lock on %s" % self.file_name)
            else:
                raise

        self.file.seek(0)
        self.file.truncate()
        self.file.write("{0}\n".format(os.getpid()))
        self.file.flush()

    def __exit__(self, type=None, value=None, traceback=None):
        self.file.close()
        self.file = None
        os.remove(self.file_name)

class Logger(logging.Logger):
    """ Handles logging to syslog and standard error. """

    def __init__(self, name):
        logging.Logger.__init__(self, name, logging.INFO)

        formatter = logging.Formatter(os.path.basename(sys.argv[0]) +
                                      ": %(message)s")

        stream = logging.StreamHandler()
        stream.setFormatter(formatter)
        self.addHandler(stream)

        self.syslog = logging.handlers.SysLogHandler("/dev/log",
                                     logging.handlers.SysLogHandler.LOG_DAEMON)

        self.syslog.setFormatter(formatter)
        self.addHandler(self.syslog)

def main():
    """Entry point"""
    logging.setLoggerClass(Logger)
    global log
    log = logging.getLogger(os.path.basename(sys.argv[0]))
    try:
        args = parse_args()
        if args.debug:
            log.setLevel(logging.DEBUG)

        domstore = Domstore()
        configs = Config(domstore).syncs
        syncs = [Sync(s, args.once, args.debug) for s in configs]
        with daemon_context(args.foreground):
            run(syncs, args.once)
    except ConfigError as exc:
        log.error("configuration error: %s", exc)
        sys.exit(1)
    except Error as exc:
        log.error("error: %s", exc)
        sys.exit(1)
    except Exception:
        for line in traceback.format_exc().splitlines():
            log.error("%s", line)
        sys.exit(1)
