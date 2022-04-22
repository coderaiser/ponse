'use strict';

const {test, stub} = require('supertape');

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
    
    t.equal(status, 404);
    t.end();
});

test('ponse: path traversal: message', async (t) => {
    const options = {
        root: __dirname,
    };
    const request = {
        url: '/../../../../../../../../etc/passwd',
    };
    
    const response = {
        send: stub(),
        setHeader: stub(),
        end: stub(),
    };
    
    await ponse._getStatic(options, request, response);
    const expect = `Path /etc/passwd beyond root ${__dirname}!`;
    
    t.calledWith(response.end, [expect]);
    t.end();
});

test('ponse: path traversal: status: ok', async (t) => {
    const {status} = await request.get('/ponse.js', {
        options: {
            root: __dirname,
        },
    });
    
    t.equal(status, 200);
    t.end();
});

test('ponse: path traversal: status: ok: changed root', async (t) => {
    const {status} = await request.get('/ponse.js', {
        options: {
            root: `${__dirname}/../lib`,
        },
    });
    
    t.equal(status, 200);
    t.end();
});

test('ponse: getPathName: res', (t) => {
    const url = '/hello?world=1';
    const name = getPathName({
        url,
    });
    
    t.equal(name, '/hello');
    t.end();
});

test('ponse: getPathName: nbsp', (t) => {
    const url = '/hello&nbsp;world?world=1';
    const name = getPathName({
        url,
    });
    
    t.equal(name, '/hello\xa0world');
    t.end();
});

test('ponse: getPathName: string', (t) => {
    const url = '/hello?world=1';
    const name = getPathName({
        url,
    });
    
    t.equal(name, '/hello');
    t.end();
});

test('ponse: getQuery', (t) => {
    const req = {
        url: 'hi?world',
    };
    
    const query = getQuery(req);
    
    t.equal(query, 'world');
    t.end();
});

test('ponse: getQuery: string', (t) => {
    const url = 'hi?world';
    const query = getQuery(url);
    
    t.equal(query, 'world');
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
        '320px-Floppy_disk_2009_G1': 'image/jpeg',
        '320px-Floppy_disk_2009_G1.jpg': 'image/jpeg',
        '294px-Railroad1860.png': 'image/png',
        '294px-Railroad1860': 'image/png',
        'hello.txt': 'text/plain; charset=UTF-8',
    };
    
    let file;
    
    for (file in filesToMimes) {
        const {headers} = await request.get('/' + file, {
            options: {
                root: __dirname + '/../test/fixtures/mimetype/',
            },
        });
        
        const reportedMime = headers.get('content-type');
        const expect = filesToMimes[file];
        
        t.equal(reportedMime, expect);
    }
    
    t.end();
}, {
    checkAssertionsCount: false,
});
