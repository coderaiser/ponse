'use strict';

const test = require('supertape');
const {get} = require('./connect');
const {
    getPathName,
    getQuery,
} = require('..');

test('ponse: path traversal: statusCode', async (t) => {
    const {statusCode} = await get('../../../../../../etc/passwd', __dirname);
    
    t.equal(statusCode, 404, 'should equal');
    t.end();
});

test('ponse: path traversal: message', async (t) => {
    const {body} = await get('../../../../../../etc/passwd', __dirname);
    const expect = `Path /etc/passwd beyond root ${__dirname}!`;
    
    t.equal(body, expect, 'should equal');
    t.end();
});

test('ponse: path traversal: status: ok', async (t) => {
    const {statusCode} = await get('ponse.js', __dirname);
    
    t.equal(statusCode, 200, 'should equal');
    t.end();
});

test('ponse: path traversal: status: ok', async (t) => {
    const {statusCode} = await get('ponse.js', `${__dirname}/../lib`);
    
    t.equal(statusCode, 200, 'should equal');
    t.end();
});

test('ponse: getPathName: res', (t) => {
    const url = '/hello?world=1';
    const name = getPathName({
        url,
    });
    
    t.equal(name, '/hello', 'should equal');
    t.end();
});

test('ponse: getPathName: string', (t) => {
    const url = '/hello?world=1';
    const name = getPathName(url);
    
    t.equal(name, '/hello', 'should equal');
    t.end();
});

test('ponse: getQuery', (t) => {
    const req = {
        url: 'hi?world',
    };
    
    const query = getQuery(req);
    
    t.equal(query, 'world', 'should equal');
    t.end();
});

test('ponse: getQuery: string', (t) => {
    const url = 'hi?world';
    const query = getQuery(url);
    
    t.equal(query, 'world', 'should equal');
    t.end();
});

