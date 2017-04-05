#!/bin/bash

stop_program ()
{
  pidfile=$1
  logfile=$2

  echo "Stopping Process - $pidfile. PID=$(cat $pidfile)"
  kill -9 $(cat $pidfile)
  rm $pidfile
  rm $logfile
}

stop_f_replicas()
{
    for (( c=1; c<=$(($FAULTS*3+1)); c++ ))
    do
        stop_program pids/server$c.pid logs/server$c.log
    done
}

stop_f_replicas