#!/usr/bin/python
import os
import subprocess
import sys
import signal
import multiprocessing
import threading
import time
import psutil

threads = []
keystores = []
DEFAULT_PORT = 3001
command = "mvn spring-boot:run -Dmaven.test.skip"

def start_replica(server_name, port, mode):
	tag = "[" + server_name + ":" + port + "] "
	
	fi = open(os.path.join("logs", server_name+".out"), "w")
	
	p = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, bufsize=1, universal_newlines=True, env=dict(os.environ, SERVER_NAME=server_name, SERVER_PORT=port, BAD=mode))
	for line in p.stdout:
		fi.write(line)
		fi.flush()
		print(tag+line, end='')
		
	fi.close()
			
	if p.returncode != 0:
		raise CalledProcessError(p.returncode, p.args)

def stop_threads():
	for thread in threads:
		process = psutil.Process(thread.pid)
		for proc in process.children(recursive=True):
			proc.kill()
		process.kill()

def generate_keystore(server_name):
	fname = "keystore-" + server_name+".jceks"
	try:
		os.remove(fname)
	except OSError:
		pass

	os.system("keytool -genkeypair -storetype JCEKS -alias \"asymm\" -keyalg RSA -keysize 2048 -keypass \"batata\" -validity 180 -storepass \"batata\" -keystore " + fname + " -dname \"CN=SEC, OU=DEI, O=IST, L=Lisbon, S=Lisbon, C=PT\"")
		
def main():
	if len(sys.argv) < 2 or not sys.argv[1].isdigit():
		print("Usage: " + sys.argv[0] + " number_faults")
		sys.exit(1)
		
	number_faults = eval(sys.argv[1])
	print("Tolerating " + sys.argv[1] + " faults")
	
	for i in range(number_faults*3+1):
		print("Generating keystore server_" + str(i))
		ks = multiprocessing.Process(target=generate_keystore, args=(("server_" + str(i)),))
		keystores.append(ks)
		ks.start()
		
	for ks in keystores:
		ks.join()
		
	if not os.path.exists("logs"):
		os.makedirs("logs")
	
	for i in range(number_faults*3+1):
		t = multiprocessing.Process(target=start_replica, args=("server_" + str(i), str(DEFAULT_PORT+i), "false"))
		threads.append(t)
		t.start()

	print("Press RETURN to terminate the replicas")
	input()
	
	print("Stopping replicas")
	stop_threads()

if __name__ == "__main__":
	main()