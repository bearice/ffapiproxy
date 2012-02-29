#!/bin/sh
git clone git://github.com/bearice/kumachan4js.git
git clone git://github.com/bearice/oauthjs.git
git clone git://github.com/developmentseed/node-sqlite3.git
cd node-sqlite3
./configure
make
cd ..
