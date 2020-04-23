'use strict';

const test = require('supertape');
const stub = require('@cloudcmd/stub');

const ponse = require('..');

const {
    getPathName,
    getQuery,
    send,
} = ponse;

const {request} = require('serve-once')(ponse.static);

test('ponse: path traversal: status', async (t) => {
    const {status} = await request.get('/../../../../../../etc/passwd', {
        options: {
            root: __dirname,
        },
    });
    
    t.equal(status, 404, 'should equal');
    t.end();
});

test('ponse: path traversal: message', async (t) => {
    const {body} = await request.get('/../../../../../../etc/passwd', {
        options: {
            root: __dirname,
        },
    });
    const expect = `Path /etc/passwd beyond root ${__dirname}!`;
    
    t.equal(body, expect, 'should equal');
    t.end();
});

test('ponse: path traversal: status: ok', async (t) => {
    const {status} = await request.get('/ponse.js', {
        options: {
            root: __dirname,
        },
    });
    
    t.equal(status, 200, 'should equal');
    t.end();
});

test('ponse: path traversal: status: ok', async (t) => {
    const {status} = await request.get('/ponse.js', {
        options: {
            root: `${__dirname}/../lib`,
        },
    });
    
    t.equal(status, 200, 'should equal');
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

test('ponse: send', (t) => {
    const request = {};
    const response = {
        writableFinished: true,
        end: stub(),
        setHeader: stub(),
    };
    
    ponse.send('hello', {
        response,
        request,
    });
    
    t.notOk(response.end.called, 'should not call response.end');
    t.end();
});

