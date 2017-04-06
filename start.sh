#!/bin/bash

mkdir -p logs
mkdir -p pids

# run_program (servername, pidfile, logfile, port)
run_program ()
{
  servername=$1
  pidfile=$2
  logfile=$3
  port=$4

  if [ -e "$pidfile" ]
  then
    echo "$servername is already running. Run 'stop.sh' if you wish to restart."
    return 0
  fi

  SERVER_NAME=$servername sh ./genKeystore.sh
  SERVER_PORT=$port SERVER_NAME=$servername mvn spring-boot:run -Dmaven.test.skip >> $logfile 2>&1 &
  PID=$!
  if [ $? -eq 0 ]
  then
    echo "Successfully started $servername. PID=$PID. Logs are at $logfile"
    echo $PID > $pidfile
    return 0
  else
    echo "Could not start $servername - check logs at $logfile"
    exit 1
  fi
}

run_f_replicas()
{
    for (( c=1; c<=$(($FAULTS*3+1)); c++ ))
    do
        echo "Starting server replica $c ..."
        run_program server$c pids/server$c.pid logs/server$c.log $((3000 + $c))
    done
}

run_f_replicas