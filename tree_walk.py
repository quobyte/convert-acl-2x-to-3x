#!/usr/bin/env python3
import os
import threading
import queue

""" A parallel directory tree walk with custom callback """
__copyright__ = "Copyright 2022, Quobyte Inc"


class Callback:
    def processEntry(self, path: str) -> bool:
        """
        To return true if path points to a directory that shall be expanded
        """
        pass

    def callOnError(self, path: str, exception: Exception) -> None:
        pass


class ParallelTreeWalk:
    def __init__(self, num_threads: int, callback: Callback) -> None:
        # A FIFO queue for breadth-first traversal
        self._work_queue = queue.Queue()
        self._num_threads = num_threads
        self._callback = callback

    def start(self, path: str):
        if self._callback.processEntry(path):
            for i in range(self._num_threads):
                threading.Thread(target=self._thread_task, daemon=True).start()
            self._work_queue.put(path)

    def wait(self):
        self._work_queue.join()

    def run(self, path: str):
        self.start(path)
        self.wait()

    def _thread_task(self):
        while True:
            path = self._work_queue.get()
            try:
                for dentry in os.listdir(path):
                    dentry_path = os.path.join(path, dentry)
                    if self._callback.processEntry(dentry_path):
                        self._work_queue.put(dentry_path)
            except Exception as e:
                self._callback.callOnError(path, e)
                pass
            self._work_queue.task_done()
