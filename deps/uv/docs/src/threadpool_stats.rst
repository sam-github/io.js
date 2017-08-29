
.. _threadpool_stats:

Thread pool statistics
===========================

libuv provides a threadpool which can be used to run user code and get notified
in the loop thread. It is also used internally by libuv.  The threadpool is
global and shared across all event loops, see :c:ref:`threadpool` for more
information.

It is possible to request statistics on the threadpool activity to observe the
number of idle threads, and the number of queued work items waiting for an idle
thread to do the work. This maybe be used to detect performance problems, or to
tune the static threadpool size for a specific work load.


Data types
----------


Public members
^^^^^^^^^^^^^^



API
---

