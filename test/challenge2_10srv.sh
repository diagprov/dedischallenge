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
./keytool mkgroup groupfile10.txt localhost:2220,$PWD/ms0.pub \
                                localhost:2221,$PWD/ms1.pub \
                                localhost:2222,$PWD/ms2.pub \
                                localhost:2223,$PWD/ms3.pub \
                                localhost:2224,$PWD/ms4.pub \
                                localhost:2225,$PWD/ms5.pub \
                                localhost:2226,$PWD/ms6.pub \
                                localhost:2227,$PWD/ms7.pub \
                                localhost:2228,$PWD/ms8.pub \
                                localhost:2229,$PWD/ms9.pub \

./sthresholdserver -keyfile $PWD/ms0.pri -port 2220 >$PWD/srv0.log 2>&1 &
jobid0=$(echo $!)
echo "[*] Background server started with PID=$jobid0"
./sthresholdserver -keyfile $PWD/ms1.pri -port 2221 >$PWD/srv1.log 2>&1 &
jobid1=$(echo $!)
echo "[*] Background server started with PID=$jobid1"
./sthresholdserver -keyfile $PWD/ms2.pri -port 2222 >$PWD/srv2.log 2>&1 &
jobid2=$(echo $!)
echo "[*] Background server started with PID=$jobid1"
./sthresholdserver -keyfile $PWD/ms3.pri -port 2223 >$PWD/srv3.log 2>&1 &
jobid3=$(echo $!)
echo "[*] Background server started with PID=$jobid1"
./sthresholdserver -keyfile $PWD/ms4.pri -port 2224 >$PWD/srv4.log 2>&1 &
jobid4=$(echo $!)
echo "[*] Background server started with PID=$jobid1"
./sthresholdserver -keyfile $PWD/ms5.pri -port 2225 >$PWD/srv5.log 2>&1 &
jobid5=$(echo $!)
echo "[*] Background server started with PID=$jobid1"
./sthresholdserver -keyfile $PWD/ms6.pri -port 2226 >$PWD/srv6.log 2>&1 &
jobid6=$(echo $!)
echo "[*] Background server started with PID=$jobid1"
./sthresholdserver -keyfile $PWD/ms7.pri -port 2227 >$PWD/srv7.log 2>&1 &
jobid7=$(echo $!)
echo "[*] Background server started with PID=$jobid1"
./sthresholdserver -keyfile $PWD/ms8.pri -port 2228 >$PWD/srv8.log 2>&1 &
jobid8=$(echo $!)
echo "[*] Background server started with PID=$jobid1"
./sthresholdserver -keyfile $PWD/ms9.pri -port 2229 >$PWD/srv9.log 2>&1 &
jobid9=$(echo $!)
echo "[*] Background server started with PID=$jobid1"

sleep 1

echo "[*] Launching Client"

./sthresholdclient ./groupfile10.txt

sleep 1

echo "[*] Killing server jobs"
kill $jobid0
kill $jobid1
kill $jobid2
kill $jobid3
kill $jobid4
kill $jobid5
kill $jobid6
kill $jobid7
kill $jobid8
kill $jobid9

