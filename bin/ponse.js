#!/usr/bin/env node

import process from 'node:process';
import http from 'node:http';
import ponse from '../lib/ponse.js';

const DIR = process.cwd();
const server = http.createServer(ponse.static(DIR));

const port = process.env.PORT || 1337;
const ip = process.env.IP || '0.0.0.0';

server.listen(port, ip);

console.log('dir:', DIR);
console.log('url: http://' + ip + ':' + port);
