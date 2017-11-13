<?php

$__author__   = 'phus.lu@gmail.com';
$__version__  = '1.6.9';
$__password__ = '123456';

function encode_data($dic) {
    $a = array();
    foreach ($dic as $key => $value) {
        $a[] = $key. '=' . bin2hex($value);
    }
    return join('&', $a);
}

function decode_data($qs) {
    $dic = array();
    foreach (explode('&', $qs) as $kv) {
        $pair = explode('=', $kv, 2);
        $dic[pack('H*', $pair[0])] = $pair[1] ? pack('H*', $pair[1]) : '';
    }
    return $dic;
}

function print_response($status, $headers, $content) {
    $data['headers'] = encode_data($headers);
    $data['content'] = bin2hex($content);
    $data['code'] = $status;
    $data = base64_encode(json_encode($data));
    header('Content-Type: text/html; charset=utf-8');
    print($data);
}

function print_notify($method, $url, $status, $content) {
    $content = "<h2>PHP Fetch Server Info</h2><hr noshade='noshade'><p>$method '$url'</p><p>Return Code: $status</p><p>Message: $content</p>";
    $headers = array('content-type' => 'text/html');
    print_response($status, $headers, $content);
}

function error_exit() {
    $status = 200;
    $headers = array('content-type' => 'text/html');
    $content = "<h2>PHP Fetch Server Debug Info</h2><hr noshade='noshade'>";
    foreach (func_get_args() as $key => $value) {
        $content .= '<p>' . var_export($value, true) . '</p>';
    }
    print_response($status, $headers, $content);
    exit(0);
}

class URLFetch {
    protected $body_maxsize = 2097152;
    protected $headers = array();
    protected $body = '';
    protected $body_size = 0;

    function __construct() {
    }

    function urlfetch_curl_readheader($ch, $header) {
        $kv = array_map('trim', explode(':', $header, 2));
        if ($kv[1]) {
            $key = strtolower($kv[0]);
            $value = $kv[1];
            if ($key == 'set-cookie') {
                if (!array_key_exists('set-cookie', $this->headers)) {
                    $this->headers['set-cookie'] = $value;
                } else {
                    $this->headers['set-cookie'] .= "\r\nSet-Cookie: " . $value;
                }
            } else {
                $this->headers[$key] = $kv[1];
            }
        }
        return strlen($header);
    }

    function urlfetch_curl_readbody($ch, $data) {
        $bytes = strlen($data);
        $this->body_size += $bytes;
        $this->body .= $data;
        return $bytes;
    }

    function urlfetch_curl($url, $payload, $method, $headers) {

        $this->headers = array();
        $this->body = '';
        $this->body_size = 0;

        if ($payload) {
            $curl_opt[CURLOPT_POSTFIELDS] = $payload;
        }
        $headers['connection'] = 'close';
        $curl_opt = array();
        $curl_opt[CURLOPT_TIMEOUT]        = 16;
        $curl_opt[CURLOPT_CONNECTTIMEOUT] = 240;
        $curl_opt[CURLOPT_RETURNTRANSFER] = true;
        $curl_opt[CURLOPT_BINARYTRANSFER] = true;
        $curl_opt[CURLOPT_FAILONERROR]    = true;

        $curl_opt[CURLOPT_FOLLOWLOCATION] = false;
        $curl_opt[CURLOPT_SSL_VERIFYPEER] = false;
        $curl_opt[CURLOPT_SSL_VERIFYHOST] = false;
        $curl_opt[CURLOPT_CUSTOMREQUEST] = $method;
        switch (strtoupper($method)) {
            case 'HEAD':
                $curl_opt[CURLOPT_NOBODY] = true;
                break;
            case 'POST':
                $curl_opt[CURLOPT_POST] = true;
                break;
            default:
                break;
        }

        $header_array = array();
        foreach ($headers as $key => $value) {
            if ($key) {
                $header_array[] = join('-', array_map('ucfirst', explode('-', $key))).': '.$value;
            }
        }
        $curl_opt[CURLOPT_HTTPHEADER] = $header_array;

        $curl_opt[CURLOPT_HEADER]         = false;
        $curl_opt[CURLOPT_HEADERFUNCTION] = array(&$this, 'urlfetch_curl_readheader');
        $curl_opt[CURLOPT_WRITEFUNCTION]  = array(&$this, 'urlfetch_curl_readbody');

        $ch = curl_init($url);
        curl_setopt_array($ch, $curl_opt);
        curl_exec($ch);
        $this->headers['connection'] = 'close';
        $status_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $errno = curl_errno($ch);
        if( $errno)
        {
            $error =  $errno . ': ' .curl_error($ch);
        }
        curl_close($ch);
        $response = array('status_code' => $status_code, 'headers' => $this->headers, 'content' => $this->body, 'error' => $error);
        return $response;
    }

}

function urlfetch($url, $payload, $method, $headers) {
    $urlfetch = new URLFetch();
    return $urlfetch->urlfetch_curl($url, $payload, $method, $headers);
}

function post()
{
    global $__password__;

    $request = @gzuncompress(@file_get_contents('php://input'));
    if ($request === False) {
        return print_notify('', '', 500, 'OOPS! gzuncompress php://input error!');
    }
    $request = decode_data($request);
    return print_notify('', '', 403, '哈哈哈哈');
    $method  = $request['method'];
    $url     = $request['url'];
    $payload = $request['payload'];
    $fetchmax = $request['fetchmax'];

    if ($__password__ && $__password__ != $request['password']) {
        return print_notify($method, $url, 403, 'Wrong password.');
    }

    if (substr($url, 0, 4) != 'http') {
        return print_notify($method, $url, 501, 'Unsupported Scheme');
    }

    $headers = decode_data($request['headers']);
    $headers['connection'] = 'close';

    $errors = array();
    for ($i = 0; $i < $fetchmax; $i++) {
        $response = urlfetch($url, $payload, $method, $headers);
        $status_code = $response['status_code'];
        if (200 <= $status_code && $status_code < 400) {
            return print_response($status_code, $response['headers'], $response['content']);
        } else {
            if ($response['error']) {
                $errors[] = $response['error'];
            } else {
                $errors[] = 'URLError: ' . $status_code;
            }
        }
    }

    print_notify($request['method'], $request['url'], 502, 'PHP Fetch Server Failed: ' . var_export($errors, true));
}

function get() {
    global $__version__;

    if (@gzcompress('test') == false) {
        print_notify('GET', $_SERVER['SCRIPT_FILENAME'], 200, 'Error: need zlib moudle!');
        exit(-1);
    }

    if (!function_exists('curl_version') && !ini_get('allow_url_fopen')) {
        print_notify('GET', $_SERVER['SCRIPT_FILENAME'], 200, 'Error: need curl moudle or allow_url_fopen!');
        exit(-1);
    }

    echo <<<EOF

<html>
<head>
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
    <title>PHPAgent {$__version__} is working now</title>
</head>
<body>
    <table width="800" border="0" align="center">
        <tr><td align="center"><hr></td></tr>
        <tr><td align="center">
            <b><h1>PHPAgent {$__version__} is working now</h1></b>
        </td></tr>
        <tr><td align="center"><hr></td></tr>

        <tr><td align="center">
           PHPAgent is HTTP Porxy written by python and hosting in PHP.
        </td></tr>
        <tr><td align="center"><hr></td></tr>

        <tr><td align="center">
            For more detail,please refer to <a href="https://github.com/mytun/PHPAgent">PHPAgent Project Homepage</a>.
        </td></tr>
        <tr><td align="center"><hr></td></tr>
    </table>
</body>

EOF;
}

function main() {
    if ($_SERVER['REQUEST_METHOD'] == 'POST') {
        post();
    } else {
        get();
    }
}

main();
