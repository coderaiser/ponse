'use strict';

const fs = require('fs');
const zlib = require('zlib');
const path = require('path');
const assert = require('assert');
const {
    unescape,
} = require('querystring');

const exec = require('execon');
const type = require('itype/legacy');

const debug = require('debug');
const logData = debug('ponse:data');
const logError = debug('ponse:error');

const files = require('files-io');
const ext = require('../json/ext');

const OK = 200;
const RANGE = 206;
const MOVED_PERMANENTLY = 301;
const FILE_NOT_FOUND = 404;

const {assign} = Object;

exports.redirect    = redirect;

exports.send        = send;
exports.sendError   = sendError;
exports.sendFile    = sendFile;

exports.isGZIP      = isGZIP;

exports.getPathName = getPathName;
exports.getQuery    = getQuery;

exports.setHeader   = setHeader;

exports.static = (root, options) => {
    const dir = path.normalize(root);
    return getStatic.bind(null, dir, options);
};

/* Функция высылает ответ серверу
 * @param data
 * @param params
 * @param notLog
 */
function send(data, params) {
    const p = params;
    const {
        name = '',
        cache,
        query,
        mime,
        response,
    } = params;
    
    checkParams(params);
    
    const isGzip = p.gzip && isGZIP(p.request);
    const head = generateHeaders({
        name,
        cache,
        query,
        mime,
        gzip: isGzip,
    });
    
    fillHeader(head, response);
    
    logData(data);
    
    /* если браузер поддерживает gzip-сжатие - сжимаем данные*/
    exec.if(!isGzip,
        () => {
            if (!p.data)
                p.data = data;
            
            response.statusCode = p.status || OK;
            response.end(p.data);
        },
        
        (callback) => {
            zlib.gzip(data, (error, data) => {
                if (!error)
                    p.data = data;
                else {
                    p.status = FILE_NOT_FOUND;
                    p.data = error.message;
                }
                
                callback();
            });
        });
}

/**
 * Функция создаёт заголовки файлов
 * в зависимости от расширения файла
 * перед отправкой их клиенту
 * @param pParams
 *  name - имя файла
 * gzip - данные сжаты gzip'ом
 * query
 * https://developers.google.com/speed/docs/best-practices/caching?hl=ru#LeverageProxyCaching
 */
function generateHeaders(params) {
    let header, isContain, cmp,
        maxAge          = 31337 * 21;
    
    const p = params;
    const extension = path.extname(p.name);
    let type = p.mime || ext[extension] || 'text/plain';
    let encoding = '';
    
    isContain = /img|image|audio/.test(type);
    if (!isContain)
        encoding = '; charset=UTF-8';
    
    isContain = /download/.test(p.query);
    if (isContain)
        type = 'application/octet-stream';
    
    header          = {
        'Access-Control-Allow-Origin'   : '*',
        'Content-Type'                  : type  + encoding,
        'Vary'                          : 'Accept-Encoding',
        'Accept-Ranges'                 : 'bytes'
    };
    
    if (p.time)
        assign(header, {
            'Last-Modified' : p.time
        });
    
    if (p.range)
        assign(header, {
            'Content-Range' :   'bytes '    + p.range.start + 
                                '-'         + p.range.end   + 
                                '/'         + p.range.sizeTotal,
            
            'Content-Length':   p.range.size
        });
    else if (p.length)
        assign(header, {
            'Content-Length':   p.length
        });
    
    cmp = extension === '.appcache';
    if (!p.cache || cmp)
        maxAge  = 0;
    
    header['Cache-Control'] = 'max-age=' + maxAge;
    
    if (p.gzip)
        header['Content-Encoding']  = 'gzip';
    
    return header;
}

function setHeader(params) {
    const p = params;
    
    checkParams(params);
    
    const gzip = isGZIP(p.request) && p.gzip;
    const header = generateHeaders({
        name    : p.name,
        time    : p.time,
        range   : p.range,
        length  : p.length,
        cache   : p.cache,
        mime    : p.mime,
        gzip,
        query   : getQuery(p.request)
    });
    
    fillHeader(header, p.response);
    p.response.statusCode = p.status || OK;
}

function fillHeader(header, response) {
    const isObject = type.object(header);
    const isSent = response.headersSent;
    
    if (!isSent && isObject)
        Object.keys(header).forEach((name) => {
            response.setHeader(name, header[name]);
        });
}

/**
 * send file to client thru pipe
 * and gzip it if client support
 *
 */
function sendFile(params) {
    const p = params;
    
    checkParams(params);
    
    fs.lstat(p.name, (error, stat) => {
        if (error)
            return sendError(error, params);
        
        const isGzip = isGZIP(p.request) && p.gzip;
        const time = stat.mtime.toUTCString();
        const length = stat.size;
        const range = getRange(p.request, length);
        
        if (range)
            assign(p, {
                range,
                status: RANGE
            });
        
        assign(p, {
            time
        });
        
        if (!isGzip)
            p.length = length;
        
        setHeader(params);
        
        const options = {
            gzip    : isGzip,
            range,
        };
        
        files.pipe(p.name, p.response, options).catch((error) => {
            sendError(error, params);
        });
    });
}

/**
 * send error response
 */
function sendError(error, params) {
    checkParams(params);
    
    params.status = FILE_NOT_FOUND;
    
    const data = error.message || String(error);
    
    logError(error.stack);
    
    send(data, params);
}

function checkParams(params) {
    let ERROR = 'could not be empty!';
    let p = params;
    
    assert(params, 'params ' + ERROR);
    assert(p.request, 'p.request ' + ERROR);
    assert(p.response, 'p.response ' + ERROR);
}

function getQuery(req) {
    assert(req, 'req could not be empty!');
    const url = req.url || req;
    return url.replace(/^.*\?/, '');
}

function cutQuery(url) {
    return url.replace(/\?.*/, '');
}

function getPathName(req) {
    assert(req, 'req could not be empty!');
    
    const url = req.url || req;
    const pathname = cutQuery(url);
    // supporting of Russian language in directory names
    return unescape(pathname);
}

function getRange(req, sizeTotal) {
    let range, start, end, size, parts,
        rangeStr = req.headers.range;
    
    if (rangeStr) {
        parts   = rangeStr.replace(/bytes=/, '').split('-');
        start   = parts[0];
        end     = parts[1] || sizeTotal - 1;
        size    = (end - start) + 1;
        
        range   = {
            start       : start - 0,
            end         : end - 0,
            size        : size,
            sizeTotal   : sizeTotal
        };
    }
    
    return range;
}

function isGZIP(req) {
    let enc, is;
    
    if (req) {
        enc = req.headers['accept-encoding'] || '';
        is  = enc.match(/\bgzip\b/);
    }
    
    return is;
}

/** 
 * redirect to another URL
 */
function redirect(url, response) {
    const header  = {
        'Location': url
    };
    
    assert(url, 'url could not be empty!');
    assert(response, 'response could not be empty!');
    
    fillHeader(header, response);
    response.statusCode = MOVED_PERMANENTLY;
    response.end();
}

function getStatic(dir, options, request, response) {
    const o = options || {};
    const pathName = getPathName(request);
    const name = path.join(dir, pathName);
    
    if (name.indexOf(dir)) {
        return sendError(Error(`Path ${name} beyond root ${dir}!`), {
            request,
            response,
            name,
        });
    }
    
    let cache;
    if (type.function(o.cache))
        cache = o.cache();
    else if (o.cache !== undefined)
        cache = o.cache;
    else
        cache = true;
    
    const gzip = true;
    
    sendFile({
        name,
        cache,
        gzip,
        request,
        response,
    });
}

