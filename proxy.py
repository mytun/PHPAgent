#!/usr/bin/env python
# -*- coding: utf-8 -*-


__version__ = '1.2'
__author__ = "lxyg06@163.com"

import sys, os, re, time, errno, binascii, zlib
import struct, random, hashlib
import fnmatch, logging, ConfigParser
import threading, thread
import socket, ssl, select
import urllib2, urlparse
import BaseHTTPServer, SocketServer

try:
    import ctypes
except ImportError:
    ctypes = NoneW
try:
    import OpenSSL
except ImportError:
    OpenSSL = None
try:
    import ntlm, ntlm.HTTPNtlmAuthHandler
except ImportError:
    ntlm = None

class Common(object):
    '''global config module'''
    def __init__(self):
        ConfigParser.RawConfigParser.OPTCRE = re.compile(r'(?P<option>[^=\s][^=]*)\s*(?P<vi>[=])\s*(?P<value>.*)$')
        self.CONFIG = ConfigParser.ConfigParser()
        self.CONFIG.read(os.path.splitext(__file__)[0] + '.ini')

        self.LISTEN_VISIBLE       = self.CONFIG.getint('listen', 'visible')


        self.PHP_IP               = self.CONFIG.get('php', 'ip')
        self.PHP_PASSWORD         = self.CONFIG.get('php', 'password').strip()
        self.PHP_PORT             = self.CONFIG.getint('php', 'port')
        self.PHP_FETCHSERVER      = self.CONFIG.get('php', 'fetchserver')

        self.FETCHMAX_LOCAL       = self.CONFIG.getint('fetchmax', 'local')
        self.FETCHMAX_SERVER      = self.CONFIG.get('fetchmax', 'server')

        self.AUTORANGE_MAXSIZE    = self.CONFIG.getint('listen', 'maxsize')

        self.USERAGENT_ENABLE     = self.CONFIG.getint('useragent', 'enable')
        self.USERAGENT_STRING     = self.CONFIG.get('useragent', 'string')

        self.PHP_FETCHSERVERS     = self.PHP_FETCHSERVER.split(",")
        self.PHP_FETCHHOSTS       = []

        for i in self.PHP_FETCHSERVERS : self.PHP_FETCHHOSTS.append(re.sub(':\d+$', '', urlparse.urlparse(i).netloc))
    def install_opener(self):
        handlers = [urllib2.ProxyHandler({})]
        opener = urllib2.build_opener(*handlers)
        opener.addheaders = []
        urllib2.install_opener(opener)

    def info(self):
        info = ''
        info += '------------------------------------------------------\n'
        info += 'PHPAgent Version : %s (python/%s pyopenssl/%s)\n' % (__version__, sys.version.partition(' ')[0], (OpenSSL.version.__version__ if OpenSSL else 'Disabled'))
        info += 'PHP Mode Listen : %s:%d\n' % (self.PHP_IP, self.PHP_PORT)
        info += 'PHP FetchServer GET  : %s\n' % common.PHP_FETCHSERVERS
        info += '------------------------------------------------------\n'
        return info




class CertUtil(object):
    '''CertUtil module, based on WallProxy 0.4.0'''

    CA = None
    CALock = threading.Lock()
    ca_vendor = 'PHPAgent'
    ca_digest = 'sha256'
    ca_validity_years = 10
    ca_validity = 24 * 60 * 60 * 365 * ca_validity_years

    @staticmethod
    def readFile(filename):
        content = None
        with open(filename, 'rb') as fp:
            content = fp.read()
        return content

    @staticmethod
    def writeFile(filename, content):
        with open(filename, 'wb') as fp:
            fp.write(str(content))

    @staticmethod
    def createKeyPair(bits=1024):
        pkey = OpenSSL.crypto.PKey()
        pkey.generate_key(OpenSSL.crypto.TYPE_RSA, bits)
        return pkey

    @staticmethod
    def createCertRequest(pkey, **subj):
        req = OpenSSL.crypto.X509Req()
        req.set_version(OpenSSL.SSL.SSLv3_METHOD)
        subject = req.get_subject()
        for k,v in subj.iteritems():
            setattr(subject, k, v)
        req.set_pubkey(pkey)
        req.sign(pkey, CertUtil.ca_digest)
        return req

    @staticmethod
    def createCertificate(req, (issuerKey, issuerCert), serial,(notBefore, notAfter),extensions,sans=()):
        cert = OpenSSL.crypto.X509()
        cert.set_version(OpenSSL.SSL.SSLv3_METHOD)
        cert.set_serial_number(serial)
        cert.gmtime_adj_notBefore(notBefore)
        cert.gmtime_adj_notAfter(notAfter)
        cert.set_issuer(issuerCert.get_subject())
        cert.set_subject(req.get_subject())
        cert.set_pubkey(req.get_pubkey())
        if extensions :
            cert.add_extensions([OpenSSL.crypto.X509Extension('basicConstraints', False, 'CA:TRUE', subject=cert, issuer=cert)])
        else :
            cert.add_extensions([OpenSSL.crypto.X509Extension(b'subjectAltName', True, ', '.join('DNS: %s' % x for x in sans))])
        cert.sign(issuerKey, CertUtil.ca_digest)
        return cert

    @staticmethod
    def loadPEM(pem, type):
        handlers = ('load_privatekey', 'load_certificate_request', 'load_certificate')
        return getattr(OpenSSL.crypto, handlers[type])(OpenSSL.crypto.FILETYPE_PEM, pem)

    @staticmethod
    def dumpPEM(obj, type):
        handlers = ('dump_privatekey', 'dump_certificate_request', 'dump_certificate')
        return getattr(OpenSSL.crypto, handlers[type])(OpenSSL.crypto.FILETYPE_PEM, obj)

    @staticmethod
    def makeCA():
        pkey = CertUtil.createKeyPair(bits=4096)
        subj = {'countryName': 'CN', 'stateOrProvinceName': 'Internet',
                'localityName': 'Cernet', 'organizationName': 'PHPAgent',
                'organizationalUnitName': 'PHPAgent Root', 'commonName': 'PHPAgent CA'}
        req = CertUtil.createCertRequest(pkey, **subj)
        cert = CertUtil.createCertificate(req, (pkey, req), 0,(0, 60*60*24*7305),True)  #20 years
        return (CertUtil.dumpPEM(pkey, 0), CertUtil.dumpPEM(cert, 2))

    @staticmethod
    def get_cert_serial_number(host,cacrt):

        saltname = '%s|%s' % (cacrt.digest('sha1'), host)
        return int(hashlib.md5(saltname.encode('utf-8')).hexdigest(), 16)

    @staticmethod
    def makeCert(host, (cakey, cacrt),sans=()):
        if host[0] == '.':
            commonName = '*' + host
            organizationName = '*' + host
            sans = ['*'+host] + [x for x in sans if x != '*'+host]
        else:
            commonName = host
            organizationName = host
            sans = [host] + [x for x in sans if x != host]
        serial = CertUtil.get_cert_serial_number(host,cacrt);
        pkey = CertUtil.createKeyPair()
        subj = {'countryName': 'CN', 'stateOrProvinceName': 'Internet',
                'localityName': 'Cernet', 'organizationName': organizationName,
                'organizationalUnitName': 'PHPAgent Branch', 'commonName': commonName}
        req = CertUtil.createCertRequest(pkey, **subj)
        cert = CertUtil.createCertificate(req, (cakey, cacrt), serial,(0, 60*60*24*7305),False,sans)
        return (CertUtil.dumpPEM(pkey, 0), CertUtil.dumpPEM(cert, 2))

    @staticmethod
    def getCertificate(host, sans=(), full_name=False):
        basedir = os.path.dirname(__file__)
        if host.count('.') >= 2 and [len(x) for x in reversed(host.split('.'))] > [2, 4] and not full_name:
            host = '.'+host.partition('.')[-1]

        keyFile = os.path.join(basedir, 'certs/%s.key' % host)
        crtFile = os.path.join(basedir, 'certs/%s.crt' % host)
        if os.path.exists(keyFile):
            return (keyFile, crtFile)
        if not os.path.isfile(keyFile):
            with CertUtil.CALock:
                key, crt = CertUtil.makeCert(host, CertUtil.CA)
                CertUtil.writeFile(keyFile, key)
                CertUtil.writeFile(crtFile, crt)
        return (keyFile, crtFile)

    @staticmethod
    def checkCA():
        #Check CA exists
        basedir = os.path.dirname(__file__)
        if not os.path.exists('certs') :
            os.mkdir('certs')
        keyFile = os.path.join(basedir, 'CA.key')
        crtFile = os.path.join(basedir, 'CA.crt')
        if not os.path.exists(keyFile) or not os.path.exists(crtFile) :
            if os.path.exists(keyFile):
                os.remove('CA.key')
            if os.path.exists(crtFile):
                os.remove('CA.crt')
            key, ca = CertUtil.makeCA()
            CertUtil.writeFile(keyFile, key)
            CertUtil.writeFile(crtFile, ca)
            [os.remove(os.path.join('certs', x)) for x in os.listdir('certs')]
        cakey = CertUtil.readFile(keyFile)
        cacrt = CertUtil.readFile(crtFile)
        CertUtil.CA = (CertUtil.loadPEM(cakey, 0), CertUtil.loadPEM(cacrt, 2))

class SimpleMessageClass(object):

    def __init__(self, fp, seekable = 0):
        self.fp = fp
        self.dict = dict = {}
        self.linedict = linedict = {}
        self.headers = []
        headers_append = self.headers.append
        readline = fp.readline
        while 1:
            line = readline()
            if not line or line == '\r\n':
                break
            key, _, value = line.partition(':')
            key = key.lower()
            if value:
                dict[key] = value.strip()
                linedict[key] = line
                headers_append(line)

    def get(self, name, default=None):
        return self.dict.get(name.lower(), default)

    def iteritems(self):
        return self.dict.iteritems()

    def iterkeys(self):
        return self.dict.iterkeys()

    def itervalues(self):
        return self.dict.itervalues()

    def __getitem__(self, name):
        return self.dict[name.lower()]

    def __setitem__(self, name, value):
        key = name.lower()
        self.dict[key] = value
        self.linedict[key] = '%s: %s\r\n' % (name, value)
        self.headers = None

    def __delitem__(self, name):
        key = name.lower()
        del self.dict[key]
        del self.linedict[key]
        self.headers = None

    def __contains__(self, name):
        return name.lower() in self.dict

    def __len__(self):
        return len(self.dict)

    def __iter__(self):
        return iter(self.dict)

    def __str__(self):
        return ''.join(self.headers or self.linedict.itervalues())

class LocalProxyHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    skip_headers = frozenset(['host', 'vary', 'via', 'x-forwarded-for', 'proxy-authorization', 'proxy-connection', 'upgrade', 'keep-alive'])
    SetupLock = threading.Lock()
    MessageClass = SimpleMessageClass

    def address_string(self):
        return '%s:%s' % (self.client_address[0], self.client_address[1])

    def send_response(self, code, message=None):
        self.log_request(code)
        message = message or self.responses.get(code, ('PHPAgent Notify',))[0]
        self.wfile.write('%s %d %s\r\n' % (self.protocol_version, code, message))

    def end_error(self, code, message=None, data=None):
        if not data:
            self.send_error(code, message)
        else:
            self.send_response(code, message)
            self.wfile.write(data)
    def handle_one_request(self):
        try:
            self.raw_requestline = self.rfile.readline(65537)
            if len(self.raw_requestline) > 65536:
                self.requestline = ''
                self.request_version = ''
                self.command = ''
                self.send_error(414)
                return
            if not self.raw_requestline:
                self.close_connection = 1
                return
            if not self.parse_request():
                return
            logging.info("method===%s", self.command)
            if 'CONNECT' == self.command :
                self.do_CONNECT_Thunnel();
            else :
                self.do_METHOD_Thunnel();
            if not self.wfile.closed:
                self.wfile.flush()
        except socket.timeout, e:
            self.log_error("Request timed out: %r", e)
            self.close_connection = 1
        return

    def do_CONNECT_Thunnel(self):
        # for ssl proxy
        host, _, port = self.path.rpartition(':')
        keyFile, crtFile = CertUtil.getCertificate(host)
        self.log_request(200)
        self.connection.sendall('%s 200 OK\r\n\r\n' % self.request_version)
        try:
            self._realpath = self.path
            self._realrfile = self.rfile
            self._realwfile = self.wfile
            self._realconnection = self.connection
            self.connection = ssl.wrap_socket(self.connection, keyFile, crtFile, True)
            self.rfile = self.connection.makefile('rb', self.rbufsize)
            self.wfile = self.connection.makefile('wb', self.wbufsize)
            self.raw_requestline = self.rfile.readline()
            if self.raw_requestline == '':
                return
            self.parse_request()
            if self.path[0] == '/':
                self.path = 'https://%s%s' % (self._realpath, self.path)
                self.requestline = '%s %s %s' % (self.command, self.path, self.request_version)
            self.do_METHOD_Thunnel()
        except socket.error, e:
            logging.exception('do_CONNECT_Thunnel socket.error: %s', e)
        finally:
            try:
                self.connection.shutdown(socket.SHUT_RDWR)
            except socket.error :
                try:
                    self.connection.close();
                    del self.connection
                except:
                    pass
            self.rfile = self._realrfile
            self.wfile = self._realwfile
            self.connection = self._realconnection

    def do_METHOD_Thunnel(self):
        host = self.headers.dict.get('host') or urlparse.urlparse(self.path).netloc.partition(':')[0]
        if self.path[0] == '/':
            self.path = 'http://%s%s' % (host, self.path)
        payload_len = int(self.headers.get('content-length', 0))
        if payload_len > 0:
            payload = self.rfile.read(payload_len)
        else:
            payload = ''
        self.headers['Range'] = 'bytes=0-9'
        self.headers['Accept-Ranges'] = 'bytes'
        retval, data = self.fetch(self.path, payload, self.command, self.headers)
        try:
            if retval == -1:
                return self.end_error(502, str(data))
            code = data['code']
            headers = data['headers']
            self.log_request(code)
            respline = ''
            datasize = len(data['content'])
            if code == 206:
                logging.info('>>>>>>>>>>>>>>> old content-range=%s' %  data['headers'].get('content-range',''))
                m = re.search(r'bytes\s+(\d+)-(\d+)/(\d+)', data['headers'].get('content-range',''))
                m = map(int, m.groups())
                data['code'] = 200
                del data['headers']['content-range']
                datasize = m[2]-m[0]
                data['start'] = m[1]
                data['end'] = m[2]-1
                data['headers']['content-length'] = datasize
                respline = '%s %d %s' % (self.protocol_version, data['code'], '')
            else:
                respline = '%s %d %s' % (self.protocol_version, code, self.responses.get(code, ('PHPAgent Notify', ''))[0])
            content = '%s\r\n%s\r\n\r\n' % (respline,'\r\n'.join('%s: %s' % (k, v) for k, v in headers.iteritems()))
            self.connection.sendall(content)
            self.wfile.write(data['content'])
            if code == 206:
                self.rangefetch(data['start'],data['end'])
            if 'close' == headers.get('connection',''):
                self.close_connection = 1
        except socket.error, (err, _):
            if err in (10053, errno.EPIPE):
                return


    def rengefetchThread(self,start,end,headers,lock,nextlock,number):
        failed = 0
        logging.info('>>>>>>>>>>>>>>> number==%d' % number)
        while failed < common.FETCHMAX_LOCAL:
            headers['range'] = 'bytes=%d-%d' % (start, end)
            retval, data = self.fetch(self.path, '', self.command, headers)
            if retval != 0 or data['code'] >= 400:
                failed += 1
                seconds = random.randint(2*failed, 2*(failed+1))
                time.sleep(seconds)
                continue
            failed = 0
            lock.acquire()
            logging.info('>>>>>>>>>>>>>>> write start number==%d content-range=%d-%d' % (number, start, end))
            self.wfile.write(data['content'])
            logging.info('>>>>>>>>>>>>>>> write end number==%d content-range=%d-%d' % (number, start, end))
            lock.release()
            break
        nextlock.release()
        logging.info('>>>>>>>>>>>>>>> write end end number==%s' % number)

    def rangefetch(self, start,end):
        logging.info('>>>>>>>>>>>>>>> Range Fetch started(%r)', self.headers.get('Host'))
        failed = 0
        lock = threading.Lock()
        while start < end:
            failed += 1
            start_ = start + common.AUTORANGE_MAXSIZE - 1
            if start_ > end:
                start_ = end
            nextlock = threading.Lock()
            nextlock.acquire()
            logging.info('>>>>>>>>>>>>>>> write rengefetchThread number==%d' % failed)
            thread.start_new_thread(self.rengefetchThread , (start,start_,self.headers,lock,nextlock,failed))
            time.sleep(1)
            lock = nextlock
            start = start_
        lock.acquire()
        lock.release()
        logging.info('>>>>>>>>>>>>>>> Range Fetch ended(%r)', self.headers.get('Host'))

    def fetch(self, url, payload, method='GET', headers=''):
        if method == None:
            method = 'GET'
        errors = []
        headers = '&'.join('%s=%s' % (k, binascii.b2a_hex(v)) for k, v in self.headers.iteritems() if k not in self.skip_headers)
        params = {'url': url, 'method': method, 'headers': headers, 'payload': payload}
        if common.PHP_PASSWORD:
            params['password'] = common.PHP_PASSWORD
        if common.FETCHMAX_SERVER:
            params['fetchmax'] = common.FETCHMAX_SERVER
        if common.USERAGENT_ENABLE:
            params['useragent'] = common.USERAGENT_STRING
        logging.info('urlfetch params=%s', str(params))
        params = '&'.join('%s=%s' % (k, binascii.b2a_hex(v)) for k, v in params.iteritems())
        failed = 0
        while failed < common.FETCHMAX_LOCAL:
            try:
                data = self.urlfetch(params)
                return (0, data)
            except Exception, e:
                logging.error('urlfetch error=%s', str(e))
                errors.append(str(e))
                failed += 1
                time.sleep(failed + 1)
                continue
        return (-1, errors)

class PHPProxyHandler(LocalProxyHandler):

    comm = 0

    def urlfetch(self,params):
        PHPProxyHandler.comm = (PHPProxyHandler.comm + 1) % phpLength
        fetchserver = common.PHP_FETCHSERVERS[PHPProxyHandler.comm]
        logging.debug('fetchserver = %s',fetchserver)
        request = urllib2.Request(fetchserver, zlib.compress(params, 9))
        response = urllib2.urlopen(request)
        data = response.read()
        response.close()
        logging.info('urlfetch=== data[0] = %s', data[0])
        if data[0] == '0':
            raw_data = data[1:]
        elif data[0] == '1':
            raw_data = zlib.decompress(data[1:])
        else:
            raise ValueError('Data format not match ')
        data = {}
        data['code'], hlen, clen = struct.unpack('>3I', raw_data[:12])
        tlen = 12 + hlen + clen
        realtlen = len(raw_data)
        if realtlen == tlen:
            data['content'] = raw_data[12 + hlen:]
        elif realtlen > tlen:
            data['content'] = raw_data[12 + hlen:tlen]
        else:
            raise ValueError('Data length is short than excepted!')
        data['headers'] = dict((k, binascii.a2b_hex(v)) for k, _, v in (x.partition('=') for x in raw_data[12:12 + hlen].split('&')))  
        return data       

    def setup(self):
        PHPProxyHandler.setup      = BaseHTTPServer.BaseHTTPRequestHandler.setup
        BaseHTTPServer.BaseHTTPRequestHandler.setup(self)

class LocalProxyServer(SocketServer.ThreadingMixIn, BaseHTTPServer.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True

logging.basicConfig(level=logging.INFO, format='%(levelname)s - - %(asctime)s %(message)s', datefmt='[%d/%b/%Y %H:%M:%S]')
common = Common()
rand = random.randint(0, len(common.PHP_FETCHSERVERS)-1)
phpLength = len(common.PHP_FETCHSERVERS)

def main():
    if not OpenSSL:
        logging.critical('OpenSSL is disabled, ABORT!')
        sys.exit(-1)
    CertUtil.checkCA()
    common.install_opener()
    sys.stdout.write(common.info())
    httpd = LocalProxyServer((common.PHP_IP, common.PHP_PORT), PHPProxyHandler)
    httpd.serve_forever()

if __name__ == '__main__':
    main()
