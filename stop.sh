#!/bin/bash

stop_program ()
{
  servername=$1
  pidfile=$2
  logfile=$3

  echo "Stopping Process - $pidfile. PID=$(cat $pidfile)"
  kill -9 $(cat $pidfile)
  rm $pidfile
  rm $logfile
  rm -f keystore-$servername.jceks
}

stop_f_replicas()
{
    for (( c=1; c<=$(($FAULTS*3+1)); c++ ))
    do
        stop_program server$c pids/server$c.pid logs/server$c.log
    done
}

stop_f_replicas