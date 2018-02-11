#!/bin/bash


echo "[*] Generating keys"
./keytool gen $PWD/ms0
./keytool gen $PWD/ms1
./keytool gen $PWD/ms2
./keytool gen $PWD/ms3
./keytool gen $PWD/ms4
./keytool gen $PWD/ms5
./keytool gen $PWD/ms6
./keytool gen $PWD/ms7
./keytool gen $PWD/ms8
./keytool gen $PWD/ms9

echo "[*] Making group configuration file"
./keytool mkgroup groupfile.txt localhost:2220,$PWD/ms0.pub \
                                localhost:2221,$PWD/ms1.pub

./sthresholdserver -keyfile $PWD/ms0.pri -port 2220 &
jobid0=$(echo $!)
echo "[*] Background server started with PID=$jobid0"
./sthresholdserver -keyfile $PWD/ms1.pri -port 2221 &
jobid1=$(echo $!)
echo "[*] Background server started with PID=$jobid1"

sleep 1

echo "[*] Launching Client"

./sthresholdclient ./groupfile.txt

sleep 1

echo "[*] Killing server jobs"
kill $jobid0
kill $jobid1

