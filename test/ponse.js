'use strict';

const test = require('tape');
const {get} = require('./connect');

test('ponse: path traversal: statusCode', async (t) => {
    const {statusCode} = await get('../../../../../../etc/passwd', __dirname);
    
    t.equal(statusCode, 404, 'should equal');
    t.end();
});

test('ponse: path traversal: message', async (t) => {
    const {body} = await get('../../../../../../etc/passwd', __dirname);
    const expect = 'Path /etc/passwd beyond root /home/coderaiser/ponse/test!';
    
    t.equal(body, expect, 'should equal');
    t.end();
});

test('ponse: path traversal: status: ok', async (t) => {
    const {statusCode} = await get('ponse.js', __dirname);
    
    t.equal(statusCode, 200, 'should equal');
    t.end();
});
