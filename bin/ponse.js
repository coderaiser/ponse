#!/usr/bin/env node

'use strict';

const process = require('node:process');
const http = require('node:http');
const ponse = require('../');
const DIR = process.cwd();
const server = http.createServer(ponse.static(DIR));

const port = process.env.PORT || 1337;
const ip = process.env.IP || '0.0.0.0';

server.listen(port, ip);

console.log('dir:', DIR);
console.log('url: http://' + ip + ':' + port);
