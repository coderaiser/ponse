'use strict';

var fs = require('fs');
var zlib = require('zlib');
var url = require('url');
var path = require('path');
var assert = require('assert');
var querystring = require('querystring');

var DIR_JSON = __dirname + '/../json/';

var extend = require('extendy');
var exec = require('execon');
var type = require('itype/legacy');

var debug = require('debug');
var logData = debug('ponse:data');
var logError = debug('ponse:error');

var files = require('files-io');
var ext = require(DIR_JSON + 'ext');

var OK = 200;
var RANGE = 206;
var MOVED_PERMANENTLY = 301;
var FILE_NOT_FOUND = 404;

exports.redirect    = redirect;

exports.send        = send;
exports.sendError   = sendError;
exports.sendFile    = sendFile;

exports.isGZIP      = isGZIP;

exports.getPathName = getPathName;
exports.getQuery    = getQuery;

exports.setHeader   = setHeader;

exports.static      = function(dir, options) {
    return getStatic.bind(null, dir, options);
};

/* Функция высылает ответ серверу
 * @param data
 * @param params
 * @param notLog
 */
function send(data, params) {
    var p = params;
    var isGzip;
    var head;
    
    checkParams(params);
    
    isGzip = p.gzip && isGZIP(p.request);
    
    head = generateHeaders({
        name    : p.name,
        cache   : p.cache,
        gzip    : isGzip,
        query   : p.query,
        mime    : p.mime
    });
    
    fillHeader(head, p.response);
    
    logData(data);
    
    /* если браузер поддерживает gzip-сжатие - сжимаем данные*/
    exec.if(!isGzip,
        function() {
            if (!p.data)
                p.data = data;
            
            p.response.statusCode = p.status || OK;
            p.response.end(p.data);
        },
        
        function(callback) {
            zlib.gzip(data, function(error, data) {
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
    var header, p, extension, type, encoding, isContain, cmp,
        maxAge          = 31337 * 21;
    
    if (params.name) {
        p               = params,
        extension       = path.extname(p.name),
        type            = p.mime || ext[extension] || 'text/plain',
        encoding        = '';
        
        isContain       = /img|image|audio/.test(type);
        if (!isContain)
            encoding    = '; charset=UTF-8';
        
        isContain        = /download/.test(p.query);
        if (isContain)
            type        = 'application/octet-stream';
        
        header          = {
            'Access-Control-Allow-Origin'   : '*',
            'Content-Type'                  : type  + encoding,
            'Vary'                          : 'Accept-Encoding',
            'Accept-Ranges'                 : 'bytes'
        };
        
        if (p.time)
            extend(header, {
                'Last-Modified' : p.time
            });
        
        if (p.range)
            extend(header, {
                'Content-Range' :   'bytes '    + p.range.start + 
                                    '-'         + p.range.end   + 
                                    '/'         + p.range.sizeTotal,
                
                'Content-Length':   p.range.size
            });
        else if (p.length)
            extend(header, {
                'Content-Length':   p.length
            });
        
        cmp             = extension === '.appcache';
        if (!p.cache || cmp)
            maxAge  = 0;
        
        header['Cache-Control']     = 'max-age=' + maxAge;
        
        if (p.gzip)
            header['Content-Encoding']  = 'gzip';
    }
    
    return header;
}

function setHeader(params) {
    var header, gzip,
        p   = params;
    
    checkParams(params);
    
    gzip    = isGZIP(p.request) && p.gzip;
    
    header  = generateHeaders({
        name    : p.name,
        time    : p.time,
        range   : p.range,
        length  : p.length,
        cache   : p.cache,
        mime    : p.mime,
        gzip    : gzip,
        query   : getQuery(p.request)
    });
    
    fillHeader(header, p.response);
    p.response.statusCode = p.status || OK;
}

function fillHeader(header, response) {
    var isObject = type.object(header);
    var isSent = response.headersSent;
    
    if (!isSent && isObject)
        Object.keys(header).forEach(function(name) {
            response.setHeader(name, header[name]);
        });
}

/**
 * send file to client thru pipe
 * and gzip it if client support
 *
 */
function sendFile(params) {
    var p = params;
    
    checkParams(params);
    
    fs.lstat(p.name, function(error, stat) {
        var time, length, range, isGzip,
            options = {};
        
        if (error)
            return sendError(error, params);
        
        isGzip  = isGZIP(p.request) && p.gzip;
        time    = stat.mtime.toUTCString();
        length  = stat.size;
        range   = getRange(p.request, length);
        
        if (range)
            extend(p, {
                range: range,
                status: RANGE
            });
        
        extend(p, {
            time: time
        });
        
        if (!isGzip)
            p.length = length;
        
        setHeader(params);
        
        options = {
            gzip    : isGzip,
            range   : range
        };
        
        files.pipe(p.name, p.response, options, function(error) {
            if (error)
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
    
    var data = error.message || String(error);
    
    logError(error.stack);
    
    send(data, params);
}

function checkParams(params) {
    var ERROR = 'could not be empty!';
    var p = params;
    
    assert(params, 'params ' + ERROR);
    assert(p.name, 'p.name ' + ERROR);
    assert(p.request, 'p.request ' + ERROR);
    assert(p.response, 'p.response ' + ERROR);
}

function getQuery(req) {
    var query, parsed;
    
    assert(req, 'req could not be empty!');
    
    parsed  = url.parse(req.url);
    query   = parsed.query;
    
    return query;
}

function getPathName(req) {
    var pathname, parsed;
    
    assert(req, 'req could not be empty!');
    
    parsed      = url.parse(req.url);
    pathname    = parsed.pathname;
    /* supporting of Russian language in directory names */
    pathname    = querystring.unescape(pathname);
    
    return pathname;
}

function getRange(req, sizeTotal) {
    var range, start, end, size, parts,
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
    var enc, is;
    
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
    var header  = {
        'Location': url
    };
    
    assert(url, 'url could not be empty!');
    assert(response, 'response could not be empty!');
    
    fillHeader(header, response);
    response.statusCode = MOVED_PERMANENTLY;
    response.end();
}

function getStatic(dir, options, req, res) {
    var cache,
        o           = options || {},
        name        = getPathName(req);
    
    name            = path.join(dir, name);
    
    if (type.function(o.cache))
        cache   = o.cache();
    else if (o.cache !== undefined)
        cache   = o.cache;
    else
        cache   = true;
    
    sendFile({
        name        : name,
        cache       : cache,
        gzip        : true,
        request     : req,
        response    : res
    });
}

