const express = require('express');
const http = require('http');
const https = require('https');
const url = require('url');
const fs = require('fs');
const querystring = require('querystring');
const morgan = require('morgan');
const winston = require('winston');
const cheerio = require('cheerio');
const through2 = require('through2');
var iconv = require('iconv-lite');

const injectContent = fs.readFileSync('inject.txt', 'utf8');
const privateKey = fs.readFileSync('site.key', 'utf8');
const certificate = fs.readFileSync('site.crt', 'utf8');
const credentials = {key: privateKey, cert: certificate};

const HTTP_PORT = 80;
const SSL_PORT = 443;
const HOSTNAME = 'proxy.learn.io';

const logger = winston.createLogger({
    level: 'info',
    format: winston.format.json(),
    transports: [
        new winston.transports.File({filename: 'error.log', level: 'error'}),
        new winston.transports.File({filename: 'combined.log'})
    ]
});

if (process.env.NODE_ENV !== 'production') {
    logger.add(new winston.transports.Console({
        format: winston.format.simple()
    }));
}

const app = express();

const base64 = (() => {
    const e = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-=";
    return {
        'decode': (r) => {
            const o = String(r).replace(/=+$/, "");
            if (o.length % 4 === 1)
                return null;
            for (var n, a, i = 0, c = 0, d = ""; a = o.charAt(c++);
                 ~a && (n = i % 4 ? 64 * n + a : a, i++ % 4) ? d += String.fromCharCode(255 & n >> (-2 * i & 6)) : 0) {
                a = e.indexOf(a);
                if (a < 0 || a > 63)
                    return null;
            }
            return d;
        },
        'encode': (r) => {
            for (var o = 0, n, a = String(r), i = 0, c = e, d = ""; a.charAt(0 | i) || (c = "=", i % 1); d += c.charAt(63 & o >> 8 - i % 1 * 8)) {
                if (n = a.charCodeAt(i += .75), n > 255)
                    return null;
                o = o << 8 | n;
            }
            return d;
        }
    };
})();

const convert_internal = (r, link, ssl) => {
    if (/(https?|javascript):/.test(link))
        return link;
    if (/\/\//.test(link))
        return (ssl ? 'https:' : 'http:') + link;
    return new url.URL(link, r).href;
};

const convert_link = (r, link, ssl) => {
    if (/data:/.test(link))
        return link;
    return `https://${HOSTNAME}/proxy.html?q=${base64.encode(convert_internal(r, link, ssl))}`;
};

const convert_script = (r, link, ssl) => {
    const re = /(["'])((?:https?:)?\/\/[^'"]+?)\1/g;
    let mch,
        parsed = '',
        lastAppend = 0;

    while ((mch = re.exec(link)) !== null) {
        parsed += `${link.substring(lastAppend, mch.index)} "${convert_link(r, mch[2], ssl)}" `;
        lastAppend = re.lastIndex;
    }
    const result = parsed + link.substring(lastAppend);
    return result;
};

const formatHtml = (r, ssl) => {
    let buf = [];
    return through2((chunk, enc, next) => {
            buf.push(chunk);
            if (/<\/html>/.test(chunk.slice(chunk.length - 15)) || /<\/html>/.test(chunk.slice(chunk.length - 100))) {
                const b = Buffer.concat(buf);
                let html = b.toString('utf-8');
                let $ = cheerio.load(html);
                if (/gb2312/.test($('meta[http-equiv="Content-Type"]').attr('content'))) {
                    html = iconv.decode(b, 'gb2312');
                    $ = cheerio.load(html);
                }
                $('meta[http-equiv="refresh"]').remove();
                $('title').text(`CLIB PROXY SERVER - ${$('title').text()}`);
                $('[href]').each((i, elem) => {
                    $(elem).attr('href', convert_link(r, $(elem).attr('href'), ssl));
                });
                $('[src]').each((i, elem) => {
                    $(elem).attr('src', convert_link(r, $(elem).attr('src'), ssl));
                });
                $('script').each((i, elem) => {
                    let e = $(elem);
                    if (e.attr('src'))
                        return;
                    e.html(convert_script(r, e.html(), ssl));
                });
                $('body').prepend(injectContent);
                next(null, $.html());
            } else {
                next(null, null);
            }
        },
        (done) => {
            done();
        })
};

const get_original = (u) => {
    const _u = base64.decode(querystring.parse(url.parse(u || '').query || '')['q'] || '');
    if (_u === '')
        return null;
    return _u;
};

const logging = (tokens, req, res) => {
    const method = tokens.method(req, res);
    let _url = tokens.url(req, res);
    const path = get_original(url.parse(tokens.url(req, res)));
    if (path)
        _url = path;
    const status = tokens.status(req, res);
    const length = tokens.res(req, res, 'content-length') || '-';
    const elapsed = parseFloat(tokens['response-time'](req, res));
    let color = 32;
    if (status >= 500)
        color = 31;
    else if (status >= 400)
        color = 33;
    else if (status >= 300)
        color = 36;
    const elapsedColor = (elapsed < 500) ? 90 : 31;
    return `\x1b[90m${method} ${_url} \x1b[${color}m${status} \x1b[90m${length} \x1b[${elapsedColor}m${elapsed.toFixed(0)}ms\x1b[0m`;
};

morgan.format('short', logging);
app.use(morgan('short'));

app.use('/proxy.html', function (req, res) {
    /*if (req.protocol === 'http') {
        res.redirect(302, `https://${HOSTNAME}${req.originalUrl}`);
        return;
    }*/
    const request = req.query['q'];
    if (!request) {
        res.status(502).send({message: 'Invalid request!'});
        return;
    }
    const req_base64 = request.match(/^[0-9A-Za-z+=-]+/);
    if (!req_base64) {
        res.status(502).send({message: 'Invalid base64!'});
        return;
    }
    let r = base64.decode(req_base64[0]);
    if (!r) {
        res.status(502).send({message: 'Invalid encoding!'});
        return;
    }
    r += request.substr(req_base64[0].length);
    const _req = url.parse(r);
    if (!_req.host) {
        res.status(502).send({message: 'Invalid host!'});
        return;
    }
    const isHTTPS = _req.protocol === 'https:';
    if (/https?:\/\/www\.baidu\.com/.test(r)) {
    } else {
        if (req.headers['referer']) {
            const ref = req.headers['referer'];
            const ref_url = get_original(ref);
            if (ref_url) {
                _req.headers = {'referer': ref_url};
            } else {
                _req.headers = {'referer': _req.hostname};
            }
        } else {
            _req.headers = {'referer': _req.hostname};
        }
    }
    const __req = (isHTTPS ? https : http).request(_req, __res => {
        res.setHeader('Content-Type', __res.headers['content-type']);
        res.setHeader('X-Proxy-Origin', r);
        res.setHeader('X-Server', 'CLIB PROXY SERVER');
        if (__res.statusCode === 200 && __res.headers['content-type'] && /text\/html/.test(__res.headers['content-type'])) {
            logger.debug('reformat html code');
            __res.pipe(formatHtml(r, isHTTPS)).pipe(res);
            return;
        }
        if (__res.statusCode === 302) {
            const _u = url.parse(__res.headers['location'] || '');
            if (_u.hostname && _u.hostname !== HOSTNAME) {
                res.redirect(302, convert_link(r, __res.headers['location'], _u.protocol === 'https:'));
                return;
            }
        }
        if (__res.statusCode === 301) {
            const _u = url.parse(__res.headers['location'] || '');
            if (_u.hostname && _u.hostname !== HOSTNAME) {
                res.redirect(301, convert_link(r, __res.headers['location'], _u.protocol === 'https:'));
                return;
            }
        }
        __res.pipe(res);
    });
    __req.on("error", e => {
        logger.warn('Failed to proxy: ', e);
        res.status(502).send({message: 'Proxy failed'});
    });
    __req.end();
});

app.use('/', express.static('static'));

app.use((req, res, next) => {
    if (/hm\.baidu\.com/.test(req.hostname)) {
        res.status(502).send({message: 'Blocked!'});
        return;
    }
    if (req.headers['referer']) {
        const ref = req.headers['referer'];
        const ref_url = get_original(ref);
        if (!ref_url) {
            res.status(502).send({message: 'Proxy failed!', url: ref});
            return;
        }
        const link = convert_link(ref_url, req.originalUrl, req.protocol === 'https:');
        res.redirect(302, link);
    } else {
        if (req.hostname === 'localhost')
            res.redirect(302, convert_link('http://www.baidu.com/', '', false));
        else
            res.status(502).send({message: 'Proxy failed!'});
    }
});

http.createServer(app).listen(HTTP_PORT, () => {
    logger.info(`HTTP Server is running on port ${HTTP_PORT}`);
});
https.createServer(credentials, app).listen(SSL_PORT, () => {
    logger.info(`HTTPS Server is running on port ${SSL_PORT}`);
});