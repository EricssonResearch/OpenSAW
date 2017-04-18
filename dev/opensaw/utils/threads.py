"""
    Open Security Analysis Workbench (OpenSAW) - A concolic security test tool
    Copyright (C) 2016 Ericsson AB

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; version 2 of the License.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
"""

# Module for threading helper classes and functions.

# Imports
from __future__ import print_function

from sys import stderr
import threading
import cProfile
import tempfile
import time
import logging
try:
    from queue import Queue, Empty, Full
except ImportError:
    # noinspection PyUnresolvedReferences
    from Queue import Queue, Empty, Full


# Thread classes

class StoppableThread(threading.Thread):
    """
    Stoppable thread subclass. The stop function is implemented by an
    event that is set when the thread is stopped.

    @ivar __stopEvent: the stop event
    @type __stopEvent: threading.Event
    """

    def __init__(self, group=None, target=None, name=None, args=(), kwargs=None):
        if kwargs is None:
            kwargs = {}
        threading.Thread.__init__(self, group, target, name, args, kwargs)
        self.daemon = True
        self.__stopEvent = threading.Event()

    def stop(self):
        """
        Stop thread.
        """
        self.__stopEvent.set()

    def is_stopped(self):
        """
        Check whether the thread has been stopped.

        @return: bool
        """
        return self.__stopEvent.is_set()


class WorkThread(StoppableThread):
    """
    Work thread subclass. The work thread has access to input and output
    work item queues. The work thread prevents access to the input queue
    whenever stopped. The work thread prevents blocking access to the
    work item queues and exceptions.

    @ivar __inQueue: the input work item queue
    @type __inQueue: (FIFO) `queue.Queue`

    @ivar __outQueue: the output work item queue
    @type __outQueue: (FIFO) `queue.Queue`
    """

    def __init__(self, in_queue, out_queue, target,
                 name=None, args=()):
        StoppableThread.__init__(self, target=target, name=name, args=args)
        self.__inQueue = in_queue
        self.__outQueue = out_queue

    def get(self):
        """
        Get a work item from the input queue if any and the thread has
        not been stopped, None otherwise.
        """
        if self.is_stopped():
            return None
        try:
            return self.__inQueue.get_nowait()
        except Empty:
            pass

    def task_done(self):
        """
        Indicate that the last dequeued work item has been processed.
        The method should be called for each successful call to get.
        """
        self.__inQueue.task_done()

    def put(self, item):
        """
        Try to put the given `item` in the output work queue and return
        `True` if the operation succeeds, `False` otherwise.
        """
        try:
            self.__outQueue.put_nowait(item)
            return True
        except Full:
            print("Queue is full, job lost?", file=stderr)
            return False


class ThreadPool(Queue):
    def __init__(self, name, size=0, threads=-1, profile=False, target=None):
        Queue.__init__(self, size)
        self.name = name
        self.__threads = []
        for i in range(threads):
            th = WorkThread(self, None, ThreadPool.worker, "%s-%d" % (name, i), (target, profile))
            self.__threads.append(th)
            th.start()

    @staticmethod
    def worker(func, profile=False):
        thread = threading.current_thread()
        if profile:
            pr = cProfile.Profile()
            pr.enable()

        while not thread.is_stopped():
            args = thread.get()
            if args is None:
                time.sleep(1)
                continue
            # args is a tuple, but func expects arguments, use *args
            func(*args)
            thread.task_done()

        if profile:
            pr.disable()
            f = tempfile.NamedTemporaryFile(mode='w+b', delete=False, prefix="thread-log-", suffix=".cprofile")
            name = f.name
            f.close()
            pr.dump_stats(name)

    def joinThreads(self):
        for t in self.__threads:
            t.join()

    def stop(self):
        for t in self.__threads:
            t.stop()

    def is_done(self):
        with self.all_tasks_done:
            return self.unfinished_tasks is 0


class MultiThreadPool():
    def __init__(self, name, threads=-1, profile=False):
        self.queues = {}
        self.funcs = {}
        self.lock = threading.Lock()
        self.name = name
        self.__threads = []
        self.keys = []

        for i in range(threads):
            th = WorkThread(self, None, MultiThreadPool.worker, "%s-%d" % (name, i), (self, profile,))
            self.__threads.append(th)
            th.start()

    def get_nowait(self):
        with self.lock:
            if len(self.keys) == 0:
                self.keys = self.queues.keys()
            while (len(self.keys) != 0):
                k = self.keys.pop()
                if k not in self.queues:
                    continue
                q = self.queues[k]
                f = self.funcs[k]
                try:
                    v = q.get_nowait()
                except Empty:
                    continue
                #IPython.embed()
                return (v,f,k)
            raise Empty()

    def put_nowait(self):
        raise Exception("Not implemented!")

    def addQueue(self,name, function, size = 0):
        if name in self.queues:
            raise Exception("Queue with name already exists!")
        with self.lock:
            self.queues[name] = Queue(size)
            self.funcs[name] = function

    def addToQueue(self, name, args):
        self.queues[name].put(args)

    def queueDone(self, name):
        return self.queues[name].unfinished_tasks == 0

    def joinQueue(self, name):
        self.queues[name].join()

    def delQueue(self, name):
        with self.lock:
            del self.queues[name]
            del self.funcs[name]


    def taskDone(self, name):
        with self.lock:
            if name not in self.queues:
                # Nobody cares that we are done, queue was deleted before we finished
                return False

            self.queues[name].task_done()
            return True

    @staticmethod
    def worker(hackish_queue, profile=False):
        thread = threading.current_thread()
        if profile:
            pr = cProfile.Profile()
            pr.enable()

        while not thread.is_stopped():
            data = thread.get()
            if data is None:
                time.sleep(1)
                continue

            args, func, name = data
            #IPython.embed()
            # args is a tuple, but func expects arguments, use *args
            func(*args)

            # Bypasses the thread.task_done to add argument name.
            hackish_queue.taskDone(name)

        if profile:
            pr.disable()
            f = tempfile.NamedTemporaryFile(mode='w+b', delete=False, prefix="thread-log-", suffix=".cprofile")
            name = f.name
            f.close()
            pr.dump_stats(name)

    def stop(self):
        for t in self.__threads:
            t.stop()

    def joinThreads(self):
        for t in self.__threads:
            t.join()

    def is_done(self):
        with self.all_tasks_done:
            return self.unfinished_tasks is 0