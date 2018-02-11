#!/bin/bash


echo "[*] Generating keys"
./keytool gen $PWD/notarytest

./notaryserver -keyfile $PWD/notarytest.pri &
jobid=$(echo $!)
echo "[*] Background server started with PID=$jobid"

sleep 1

echo "[*] Launching Client"

./notaryclient -keyfile $PWD/notarytest.pub

sleep 1

echo "[*] Killing server job"
kill $jobid

