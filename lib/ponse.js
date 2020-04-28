'use strict';

const zlib = require('zlib');
const path = require('path');
const assert = require('assert');
const {promisify} = require('util');
const {unescape} = require('querystring');
const {lstat} = require('fs').promises;

const type = require('itype');
const filetype = require('file-type');
const tryToCatch = require('try-to-catch');
const files = require('files-io');

const debug = require('debug');
const logData = debug('ponse:data');
const logError = debug('ponse:error');

const ext = require('../json/ext');

const gzip = promisify(zlib.gzip);

const OK = 200;
const RANGE = 206;
const MOVED_PERMANENTLY = 301;
const FILE_NOT_FOUND = 404;

const KILOBYTE = 1024;

const {assign} = Object;

exports.redirect = redirect;

exports.send = send;
exports.sendError = sendError;
exports.sendFile = sendFile;

exports.isGZIP = isGZIP;

exports.getPathName = getPathName;
exports.getQuery = getQuery;

exports.setHeader = setHeader;

exports.static = (options) => getStatic.bind(null, options);

/* Функция высылает ответ серверу
 * @param data
 * @param params
 * @param notLog
 */
async function send(data, params) {
    const p = params;
    const {
        name = '',
        cache,
        query,
        mime,
        response,
    } = params;
    
    checkParams(params);
    
    if (response.writableFinished)
        return;
    
    const isGzip = p.gzip && isGZIP(p.request) && data.length > KILOBYTE;
    const head = generateHeaders({
        name,
        cache,
        query,
        mime,
        gzip: isGzip,
    });
    
    fillHeader(head, response);
    
    logData(data);
    
    response.statusCode = p.status || OK;
    
    /* если браузер поддерживает gzip-сжатие - сжимаем данные*/
    if (!isGzip)
        return response.end(data);
    
    const [error, zipped] = await tryToCatch(gzip, data);
    
    if (!error)
        return response.send(zipped);
    
    response.statusCode = FILE_NOT_FOUND;
    response.end(error.message);
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
    let maxAge = 31337 * 21;
    
    const p = params;
    const extension = path.extname(p.name);
    const type = p.mime || ext[extension] || 'text/plain';
    let encoding = '';
    
    if (!/img|image|audio|video/.test(type))
        encoding = '; charset=UTF-8';
    
    const header = {
        'Access-Control-Allow-Origin'   : '*',
        'Content-Type'                  : type + encoding,
        'Vary'                          : 'Accept-Encoding',
        'Accept-Ranges'                 : 'bytes',
    };
    
    if (/download/.test(p.query)) {
        header['Content-Disposition'] = 'attachment';
    }
    
    if (p.time)
        assign(header, {
            'Last-Modified' : p.time,
        });
    
    if (p.range)
        assign(header, {
            'Content-Range' :   'bytes ' + p.range.start +
                                '-' + p.range.end +
                                '/' + p.range.sizeTotal,
            
            'Content-Length':   p.range.size,
        });
    else if (p.length)
        assign(header, {
            'Content-Length':   p.length,
        });
    
    const cmp = extension === '.appcache';
    
    if (!p.cache || cmp)
        maxAge = 0;
    
    header['Cache-Control'] = 'max-age=' + maxAge;
    
    if (p.gzip)
        header['Content-Encoding'] = 'gzip';
    
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
        query   : getQuery(p.request),
    });
    
    fillHeader(header, p.response);
    p.response.statusCode = p.status || OK;
}

function fillHeader(header, response) {
    const isObject = type.object(header);
    const isSent = response.headersSent;
    
    if (!isSent && isObject)
        for (const name of Object.keys(header)) {
            response.setHeader(name, header[name]);
        }
}

/**
 * send file to client thru pipe
 * and gzip it if client support
 *
 */
async function sendFile(params) {
    checkParams(params);
    
    const p = params;
    const [error, stat] = await tryToCatch(lstat, p.name);
    
    if (error)
        return sendError(error, params);
    
    const isGzip = isGZIP(p.request) && p.gzip;
    const time = stat.mtime.toUTCString();
    const length = stat.size;
    const range = getRange(p.request, length);
    
    if (range)
        assign(p, {
            range,
            status: RANGE,
        });
    
    assign(p, {
        time,
    });
    
    if (!isGzip)
        p.length = length;
    
    const [, type] = await tryToCatch(filetype.fromFile, p.name);
    
    if (type)
        p.mime = type.mime;
    
    setHeader(params);
    
    const options = {
        gzip: isGzip,
        range,
    };
    
    const [pipeError] = await tryToCatch(files.pipe, p.name, p.response, options);
    
    if (pipeError)
        sendError(pipeError, params);
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
    const ERROR = 'could not be empty!';
    const p = params;
    
    assert(params, 'params ' + ERROR);
    assert(p.request, 'p.request ' + ERROR);
    assert(p.response, 'p.response ' + ERROR);
}

function getQuery(req) {
    assert(req, 'req could not be empty!');
    const {
        url = req,
    } = req;
    return url.replace(/^.*\?/, '');
}

function cutQuery(url) {
    return url.replace(/\?.*/, '');
}

function getPathName(req) {
    assert(req, 'req could not be empty!');
    
    const {
        url = req,
    } = req;
    const pathname = cutQuery(url);
    // supporting of Russian language in directory names
    return unescape(pathname);
}

function getRange(req, sizeTotal) {
    let range;
    let start;
    let end;
    let size;
    let parts;
    const rangeStr = req.headers.range;
    
    if (rangeStr) {
        parts = rangeStr.replace(/bytes=/, '').split('-');
        [start] = parts;
        end = parts[1] || sizeTotal - 1;
        size = end - start + 1;
        
        range = {
            start       : start - 0,
            end         : end - 0,
            size,
            sizeTotal,
        };
    }
    
    return range;
}

function isGZIP(req) {
    const enc = req.headers['accept-encoding'] || '';
    const is = /\bgzip\b/.test(enc);
    
    return is;
}

/**
 * redirect to another URL
 */
function redirect(url, response) {
    const header = {
        Location: url,
    };
    
    assert(url, 'url could not be empty!');
    assert(response, 'response could not be empty!');
    
    fillHeader(header, response);
    response.statusCode = MOVED_PERMANENTLY;
    response.end();
}

function getStatic(options, request, response) {
    const o = options || {};
    const {root} = options;
    const dir = path.normalize(root);
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
