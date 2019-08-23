'use strict';

const http = require('http');

const got = require('got');
const {promisify} = require('util');
const ponse = require('..');

const getURL = (path, port) => `http://127.0.0.1:${port}/${path}`;

const serve = promisify((dir, fn) => {
    const server = http.createServer(ponse.static(dir));
    const done = () => server.close();
    
    server.listen(() => {
        const {port} = server.address();
        
        fn(null, {
            port,
            done,
        });
    });
});

module.exports.serve = serve;

module.exports.get = async (path, root) => {
    const {port, done} = await serve(root);
    const url = getURL(path, port);
    
    const res = await got(url, {
        throwHttpErrors: false,
    });
    
    done();
    
    return res;
};

