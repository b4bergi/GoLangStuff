#!/bin/bash
subjectHash=`openssl x509 -inform PEM -subject_hash_old -in cert.pem | head -n 1`
openssl x509 -in cert.pem -inform PEM -outform DER -out $subjectHash.0
adb root adb push ./$subjectHash.0 /data/misc/user/0/cacerts-added/$subjectHash.0
adb shell "su 0 chmod 644 /data/misc/user/0/cacerts-added/$subjectHash.0"
adb reboot
