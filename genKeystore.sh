#!/bin/sh
rm -f keystore.jceks
keytool -genkeypair -storetype JCEKS -alias "asymm" -keyalg RSA -keysize 2048 -keypass "batata" -validity 180 -storepass "batata" -keystore keystore.jceks -dname "CN=SEC, OU=DEI, O=IST, L=Lisbon, S=Lisbon, C=PT"