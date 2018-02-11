#!/bin/bash


echo "[*] Generating keys"
./keytool gen $PWD/ms0
./keytool gen $PWD/ms1

echo "[*] Making group configuration file"
./keytool mkgroup groupfile.txt localhost:2220,$PWD/ms0.pub \
                                localhost:2221,$PWD/ms1.pub

./sthresholdserver -keyfile $PWD/ms0.pri -port 2220 >$PWD/srv0.log 2>&1 &
jobid0=$(echo $!)
echo "[*] Background server started with PID=$jobid0"
./sthresholdserver -keyfile $PWD/ms1.pri -port 2221 >$PWD/srv1.log 2>&1 &
jobid1=$(echo $!)
echo "[*] Background server started with PID=$jobid1"

sleep 1

echo "[*] Launching Client"

./sthresholdclient ./groupfile.txt

sleep 1

echo "[*] Killing server jobs"
kill $jobid0
kill $jobid1

