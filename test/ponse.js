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
    
    send('hello', {
        response,
        request,
    });
    
    t.notOk(response.end.called, 'should not call response.end');
    t.end();
});

test('ponse: get: content-type', async (t) => {
    const filesToMimes = {
        "320px-Floppy_disk_2009_G1" : "image/jpeg",
        "320px-Floppy_disk_2009_G1.jpg" : "image/jpeg",
        "294px-Railroad1860.png" : "image/png",
        "294px-Railroad1860" : "image/png",
        "hello.txt" : "text/plain; charset=UTF-8",
    }

    var file;
    for (file in filesToMimes) {
        const {headers} = await request.get('/' + file, {
            options: {
                root: __dirname + '/../test/fixtures/mimetype/',
            },
        });

        const reportedMime = headers.get('content-type');
        const expect = filesToMimes[file]

        t.equal(reportedMime, expect, 'should equal')
    }

    t.end();
});
