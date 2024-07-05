#ifndef PROCESSCAPTURER_H
#define PROCESSCAPTURER_H

class ProcessCapturer {
 private:
  DWORD pid;
  int suspendThreadPtr;
  boolean isSuspended;

 public:
  /**
   * The PID is used for determining whether the process is Wow64 or not (which
   * impacts the SuspendThread call)
   */
  ProcessCapturer(int pid);

  void pauseProcess();

  void resumeProcess();

  void killProcess();

  void getPid();

 private:
  void setSuspendPtr(int ThreadSuspendFunction);

 public:
  boolean isSuspended();

  void getMemoryChunk(int start, int size);
};

#endif
