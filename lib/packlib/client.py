# -*- coding: utf-8 -*-

'''
    LibraryPack for the Kodi Media Center
    Kodi is a registered trademark of the XBMC Foundation.
    We are not connected to or in any other way affiliated with Kodi - DMCA: legal@tvaddons.co

        License summary below, for more details please read license.txt file

        This program is free software: you can redistribute it and/or modify
        it under the terms of the GNU General Public License as published by
        the Free Software Foundation, either version 2 of the License, or
        (at your option) any later version.
        This program is distributed in the hope that it will be useful,
        but WITHOUT ANY WARRANTY; without even the implied warranty of
        MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
        GNU General Public License for more details.
        You should have received a copy of the GNU General Public License
        along with this program.  If not, see <http://www.gnu.org/licenses/>.
'''

from __future__ import absolute_import
from kodi_six import xbmc
from packlib import cache, dom_parser, log_utils, workers
import base64
import gzip
from random import choice
import re
import sys
import time
import six

HTMLParser = six.moves.html_parser.HTMLParser
StringIO = six.StringIO
cookielib = six.moves.http_cookiejar
quote_plus = six.moves.urllib.parse.quote_plus
urlencode = six.moves.urllib.parse.urlencode
urlparse = six.moves.urllib.parse.urlparse
urljoin = six.moves.urllib.parse.urljoin
ProxyHandler = six.moves.urllib.request.ProxyHandler
HTTPHandler = six.moves.urllib.request.HTTPHandler
HTTPSHandler = six.moves.urllib.request.HTTPSHandler
HTTPErrorProcessor = six.moves.urllib.request.HTTPErrorProcessor
build_opener = six.moves.urllib.request.build_opener
install_opener = six.moves.urllib.request.install_opener
HTTPCookieProcessor = six.moves.urllib.request.HTTPCookieProcessor
urlopen = six.moves.urllib.request.urlopen
Request = six.moves.urllib.request.Request
HTTPError = six.moves.urllib.error.HTTPError
iteritems = six.iteritems


def request(url, close=True, redirect=True, error=False, proxy=None, post=None, headers=None, mobile=False, XHR=False,
            limit=None, referer=None, cookie=None, compression=True, output='', timeout='30'):
    try:
        handlers = []

        if proxy is not None:
            handlers += [ProxyHandler({'http': '%s' % (proxy)}), HTTPHandler]
            opener = build_opener(*handlers)
            install_opener(opener)

        if output == 'cookie' or output == 'extended' or not close == True:
            cookies = cookielib.LWPCookieJar()
            handlers += [HTTPHandler(), HTTPSHandler(), HTTPCookieProcessor(cookies)]
            opener = build_opener(*handlers)
            install_opener(opener)

        if (2, 7, 8) < sys.version_info < (2, 7, 12):
            try:
                import ssl
                ssl_context = ssl.create_default_context()
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE
                handlers += [HTTPSHandler(context=ssl_context)]
                opener = build_opener(*handlers)
                install_opener(opener)
            except:
                pass

        if url.startswith('//'): url = 'http:' + url

        try:
            headers.update(headers)
        except:
            headers = {}
        if 'User-Agent' in headers:
            pass
        elif mobile is not True:
            # headers['User-Agent'] = agent()
            headers['User-Agent'] = cache.get(randomagent, 1)
        else:
            headers['User-Agent'] = 'Apple-iPhone/701.341'
        if 'Referer' in headers:
            pass
        elif referer is not None:
            headers['Referer'] = referer
        if not 'Accept-Language' in headers:
            headers['Accept-Language'] = 'en-US'
        if 'X-Requested-With' in headers:
            pass
        elif XHR is True:
            headers['X-Requested-With'] = 'XMLHttpRequest'
        if 'Cookie' in headers:
            pass
        elif cookie is not None:
            headers['Cookie'] = cookie
        if 'Accept-Encoding' in headers:
            pass
        elif compression and limit is None:
            headers['Accept-Encoding'] = 'gzip'

        if redirect is False:

            class NoRedirection(HTTPErrorProcessor):
                def http_response(self, request, response): return response

            opener = build_opener(NoRedirection)
            install_opener(opener)

            try:
                del headers['Referer']
            except:
                pass

        if isinstance(post, dict):
            post = urlencode(post)

        request = Request(url, data=post)
        _add_request_header(request, headers)

        try:
            response = urlopen(request, timeout=int(timeout))
        except HTTPError as response:

            if response.code == 503:
                cf_result = response.read(5242880)
                try:
                    encoding = response.info().getheader('Content-Encoding')
                except:
                    encoding = None
                if encoding == 'gzip':
                    cf_result = gzip.GzipFile(fileobj=StringIO(cf_result)).read()

                if 'cf-browser-verification' in cf_result:

                    netloc = '%s://%s' % (urlparse.urlparse(url).scheme, urlparse.urlparse(url).netloc)

                    ua = headers['User-Agent']

                    cf = cache.get(cfcookie().get, 168, netloc, ua, timeout)

                    headers['Cookie'] = cf

                    request = Request(url, data=post)
                    _add_request_header(request, headers)

                    response = urlopen(request, timeout=int(timeout))
                else:
                    log_utils.log('Request-Error (%s): %s' % (str(response.code), url), xbmc.LOGDEBUG)
                    if error is False:
                        return
            else:
                log_utils.log('Request-Error (%s): %s' % (str(response.code), url), xbmc.LOGDEBUG)
                if error is False:
                    return

        if output == 'cookie':
            try:
                result = '; '.join(['%s=%s' % (i.name, i.value) for i in cookies])
            except:
                pass
            try:
                result = cf
            except:
                pass
            if close is True:
                response.close()
            return result

        elif output == 'geturl':
            result = response.geturl()
            if close == True: response.close()
            return result

        elif output == 'headers':
            result = response.headers
            if close == True: response.close()
            return result

        elif output == 'chunk':
            try:
                content = int(response.headers['Content-Length'])
            except:
                content = (2049 * 1024)
            if content < (2048 * 1024): return
            result = response.read(16 * 1024)
            if close == True: response.close()
            return result

        if limit == '0':
            result = response.read(224 * 1024)
        elif limit is not None:
            result = response.read(int(limit) * 1024)
        else:
            result = response.read(5242880)

        try:
            encoding = response.info().getheader('Content-Encoding')
        except:
            encoding = None
        if encoding == 'gzip':
            result = gzip.GzipFile(fileobj=StringIO(result)).read()

        if 'sucuri_cloudproxy_js' in result:
            su = sucuri().get(result)

            headers['Cookie'] = su

            request = Request(url, data=post)
            _add_request_header(request, headers)

            response = urlopen(request, timeout=int(timeout))

            if limit == '0':
                result = response.read(224 * 1024)
            elif limit is not None:
                result = response.read(int(limit) * 1024)
            else:
                result = response.read(5242880)

            try:
                encoding = response.info().getheader('Content-Encoding')
            except:
                encoding = None
            if encoding == 'gzip':
                result = gzip.GzipFile(fileobj=StringIO(result)).read()

        if 'Blazingfast.io' in result and 'xhr.open' in result:
            netloc = '%s://%s' % (urlparse.urlparse(url).scheme, urlparse.urlparse(url).netloc)
            ua = headers['User-Agent']
            headers['Cookie'] = cache.get(bfcookie().get, 168, netloc, ua, timeout)

            result = _basic_request(url, headers=headers, post=post, timeout=timeout, limit=limit)

        if output == 'extended':
            try:
                response_headers = dict(response.info().items())
            except:
                response_headers = response.headers
            response_code = str(response.code)
            try:
                cookie = '; '.join(['%s=%s' % (i.name, i.value) for i in cookies])
            except:
                pass
            try:
                cookie = cf
            except:
                pass
            if close == True: response.close()
            return (result, response_code, response_headers, headers, cookie)
        else:
            if close == True: response.close()
            return result
    except Exception as e:
        log_utils.log('Request-Error: (%s) => %s' % (str(e), url), xbmc.LOGDEBUG)
        return


def _basic_request(url, headers=None, post=None, timeout='30', limit=None):
    try:
        try:
            headers.update(headers)
        except:
            headers = {}

        request = Request(url, data=post)
        _add_request_header(request, headers)
        response = urlopen(request, timeout=int(timeout))
        return _get_result(response, limit)
    except:
        return


def _add_request_header(_request, headers):
    try:
        if not headers:
            headers = {}

        try:
            scheme = _request.get_type()
        except:
            scheme = 'http'

        referer = headers.get('Referer') if 'Referer' in headers else '%s://%s' % (scheme, _request.get_host())

        _request.add_unredirected_header('Host', _request.get_host())
        _request.add_unredirected_header('Referer', referer)
        for key in headers: _request.add_header(key, headers[key])
    except:
        return


def _get_result(response, limit=None):
    if limit == '0':
        result = response.read(224 * 1024)
    elif limit:
        result = response.read(int(limit) * 1024)
    else:
        result = response.read(5242880)

    try:
        encoding = response.info().getheader('Content-Encoding')
    except:
        encoding = None
    if encoding == 'gzip':
        result = gzip.GzipFile(fileobj=StringIO(result)).read()

    return result


def parseDOM(html, name='', attrs=None, ret=False):
    if attrs:
        attrs = dict((key, re.compile(value + ('$' if value else ''))) for key, value in iteritems(attrs))
    results = dom_parser.parse_dom(html, name, attrs, ret)
    if ret:
        results = [result.attrs[ret.lower()] for result in results]
    else:
        results = [result.content for result in results]
    return results


def replaceHTMLCodes(txt):
    txt = re.sub("(&#[0-9]+)([^;^0-9]+)", "\\1;\\2", txt, flags=re.I)
    txt = HTMLParser.HTMLParser().unescape(txt)
    txt = txt.replace("&quot;", "\"")
    txt = txt.replace("&amp;", "&")
    txt = txt.replace("&Quot;", "\"")
    txt = txt.replace("&Amp;", "&")
    txt = txt.replace("&quot;", "\"")
    txt = txt.replace("&amp;", "&")
    txt = txt.strip()
    return txt


def randomagent():
    agents = [
        'Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.116 Safari/537.36 Edge/15.15063',
        'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:56.0) Gecko/20100101 Firefox/56.0',
        'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.87 Safari/537.36 OPR/43.0.2442.991',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_2) AppleWebKit/604.4.7 (KHTML, like Gecko) Version/11.0.2 Safari/604.4.7',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.100 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.12; rv:54.0) Gecko/20100101 Firefox/54.0',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.157 Safari/537.36',
        'Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0'
    ]

    return choice(agents)


def agent():
    return 'Mozilla/5.0 (compatible, MSIE 11, Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko'


class cfcookie:

    def __init__(self):
        self.cookie = None

    def get(self, netloc, ua, timeout):
        threads = []

        for i in range(0, 15): threads.append(workers.Thread(self.get_cookie, netloc, ua, timeout))
        [i.start() for i in threads]

        for i in range(0, 30):
            if not self.cookie is None: return self.cookie
            time.sleep(1)

    def get_cookie(self, netloc, ua, timeout):
        try:
            headers = {'User-Agent': ua}

            request = Request(netloc)
            _add_request_header(request, headers)

            try:
                response = urlopen(request, timeout=int(timeout))
            except HTTPError as response:
                result = response.read(5242880)
                try:
                    encoding = response.info().getheader('Content-Encoding')
                except:
                    encoding = None
                if encoding == 'gzip':
                    result = gzip.GzipFile(fileobj=StringIO(result)).read()

            jschl = re.findall('name="jschl_vc" value="(.+?)"/>', result)[0]

            init = re.findall('setTimeout\(function\(\){\s*.*?.*:(.*?)};', result)[-1]

            builder = re.findall(r"challenge-form\'\);\s*(.*)a.v", result)[0]

            decryptVal = self.parseJSString(init)

            lines = builder.split(';')

            for line in lines:

                if len(line) > 0 and '=' in line:
                    sections = line.split('=')
                    line_val = self.parseJSString(sections[1])
                    decryptVal = int(eval(str(decryptVal) + sections[0][-1] + str(line_val)))

            answer = decryptVal + len(urlparse.urlparse(netloc).netloc)

            query = '%s/cdn-cgi/l/chk_jschl?jschl_vc=%s&jschl_answer=%s' % (netloc, jschl, answer)

            if 'type="hidden" name="pass"' in result:
                passval = re.findall('name="pass" value="(.*?)"', result)[0]
                query = '%s/cdn-cgi/l/chk_jschl?pass=%s&jschl_vc=%s&jschl_answer=%s' % (
                    netloc, quote_plus(passval), jschl, answer)
                time.sleep(6)

            cookies = cookielib.LWPCookieJar()
            handlers = [HTTPHandler(), HTTPSHandler(), HTTPCookieProcessor(cookies)]
            opener = build_opener(*handlers)
            install_opener(opener)

            try:
                request = Request(query)
                _add_request_header(request, headers)
                response = urlopen(request, timeout=int(timeout))
            except:
                pass

            cookie = '; '.join(['%s=%s' % (i.name, i.value) for i in cookies])

            if 'cf_clearance' in cookie: self.cookie = cookie
        except:
            pass

    def parseJSString(self, s):
        try:
            offset = 1 if s[0] == '+' else 0
            val = int(
                eval(s.replace('!+[]', '1').replace('!![]', '1').replace('[]', '0').replace('(', 'str(')[offset:]))
            return val
        except:
            pass


class bfcookie:

    def __init__(self):
        self.COOKIE_NAME = 'BLAZINGFAST-WEB-PROTECT'

    def get(self, netloc, ua, timeout):
        try:
            headers = {'User-Agent': ua, 'Referer': netloc}
            result = _basic_request(netloc, headers=headers, timeout=timeout)

            match = re.findall('xhr\.open\("GET","([^,]+),', result)
            if not match:
                return False

            url_Parts = match[0].split('"')
            url_Parts[1] = '1680'
            url = urljoin(netloc, ''.join(url_Parts))

            match = re.findall('rid=([0-9a-zA-Z]+)', url_Parts[0])
            if not match:
                return False

            headers['Cookie'] = 'rcksid=%s' % match[0]
            result = _basic_request(url, headers=headers, timeout=timeout)
            return self.getCookieString(result, headers['Cookie'])
        except:
            return

    # not very robust but lazieness...
    def getCookieString(self, content, rcksid):
        vars = re.findall('toNumbers\("([^"]+)"', content)
        value = self._decrypt(vars[2], vars[0], vars[1])
        cookie = "%s=%s;%s" % (self.COOKIE_NAME, value, rcksid)
        return cookie

    def _decrypt(self, msg, key, iv):
        from binascii import unhexlify, hexlify
        from packlib import pyaes
        msg = unhexlify(msg)
        key = unhexlify(key)
        iv = unhexlify(iv)
        if len(iv) != 16: return False
        decrypter = pyaes.Decrypter(pyaes.AESModeOfOperationCBC(key, iv))
        plain_text = decrypter.feed(msg)
        plain_text += decrypter.feed()
        f = hexlify(plain_text)
        return f


class sucuri:

    def __init__(self):
        self.cookie = None

    def get(self, result):
        try:
            s = re.compile("S\s*=\s*'([^']+)").findall(result)[0]
            s = base64.b64decode(s)
            s = s.replace(' ', '')
            s = re.sub('String\.fromCharCode\(([^)]+)\)', r'chr(\1)', s)
            s = re.sub('\.slice\((\d+),(\d+)\)', r'[\1:\2]', s)
            s = re.sub('\.charAt\(([^)]+)\)', r'[\1]', s)
            s = re.sub('\.substr\((\d+),(\d+)\)', r'[\1:\1+\2]', s)
            s = re.sub(';location.reload\(\);', '', s)
            s = re.sub(r'\n', '', s)
            s = re.sub(r'document\.cookie', 'cookie', s)

            cookie = ''
            exec(s)
            self.cookie = re.compile('([^=]+)=(.*)').findall(cookie)[0]
            self.cookie = '%s=%s' % (self.cookie[0], self.cookie[1])

            return self.cookie
        except:
            pass
