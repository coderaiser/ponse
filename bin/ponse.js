#!/usr/bin/env node

'use strict';

const DIR = process.cwd();

const ponse = require('../');
const http = require('http');

const server = http.createServer(ponse.static(DIR));

const port  =   process.env.PORT            ||  /* c9           */
                process.env.app_port        ||  /* nodester     */
                process.env.VCAP_APP_PORT   ||  /* cloudfoundry */
                1337;

const ip =   process.env.IP              ||  /* c9           */
                    '0.0.0.0';

server.listen(port, ip);

console.log('dir:', DIR);
console.log('url: http://' + ip + ':' + port);
