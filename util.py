import os
def kill_process(*pids):
  for pid in pids:
    a = os.kill(pid, signal.SIGKILL)
    print('已杀死pid为%s的进程,　返回值是:%s' % (pid, a))

def get_pid(*ports):
	#其中\"为转义"
  pids = []
  for port in ports:
    pid = os.popen("netstat -nlp | grep :%s | awk '{print $7}' | awk -F\" / \" '{ print $1 }'" % (port)).read().split('/')[0]
    if pid:
      pids.append(int(pid))
  return pids

  kill_process(*get_pid(["5000"]))