#!/usr/bin/env python3

import base64
import json
import re
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs

PORT = 8042

class MockServerRequestHandler(BaseHTTPRequestHandler):

    DEVICECODE_PATTERN = re.compile(r'/devicecode')
    TOKEN_PATTERN = re.compile(r'/token')
    USERINFO_PATTERN = re.compile(r'/userinfo')
    CLIENT_ID = 'client_id'
    CLIENT_SECRET = 'NDVmODY1ZDczMGIyMTM1MWFlYWM2NmYw'
    SCOPE = 'openid profile'
    USER_CODE = 'QWERTY'
    DEVICE_CODE = 'e1e9b7be-e720-467e-bbe1-5c382356e4a9'
    ACCESS_TOKEN  = 'ZjBhNTQxYzEzMGQwNWU1OWUxMDhkMTM5'
    VERIFICATION_URL = 'http://localhost:{}/oidc/device'.format(PORT)

    def do_GET(self):
        if re.search(self.USERINFO_PATTERN, self.path):
            if 'Bearer ' + self.ACCESS_TOKEN in self.headers.get('Authorization', ''):
                response_data = {
                    'sub': 'YzQ4YWIzMzJhZjc5OWFkMzgwNmEwM2M5',
                    'preferred_username': 'jdoe',
                    'name': 'Joe Doe'
                }
                self.send_response(200)
                self.end_headers()
                self.wfile.write(json.dumps(response_data).encode())
            else:
                self.send_response(403)
                self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()
    def do_POST(self):
        body = self.rfile.read(int(self.headers['Content-Length'])).decode()
        post_data = parse_qs(body)
        if re.search(self.DEVICECODE_PATTERN, self.path):
            if (post_data['client_id'] == [self.CLIENT_ID] and
                    post_data['scope'] == [self.SCOPE]):
                response_data = {
                    'user_code': self.USER_CODE,
                    'verification_uri': self.VERIFICATION_URL,
                    'verification_uri_complete': '{}?user_code={}'.format(
                        self.VERIFICATION_URL, self.DEVICE_CODE),
                    'device_code': self.DEVICE_CODE,
                    'error': None,
                    'expires_in': 1800
                }
                self.send_response(200)
                self.end_headers()
                self.wfile.write(json.dumps(response_data).encode())
            else:
                self.send_response(403)
                self.end_headers()
        elif re.search(self.TOKEN_PATTERN, self.path):
            auth = self.headers.get('Authorization', '')
            if (post_data['client_id'] == [self.CLIENT_ID] and
                    post_data['device_code'] == [self.DEVICE_CODE] and
                    post_data['grant_type'] == ['urn:ietf:params:oauth:grant-type:device_code'] and
                    'Basic' in auth and
                    base64.b64decode(auth.split()[1]).decode() == '{}:{}'.format(
                        self.CLIENT_ID, self.CLIENT_SECRET)):
                response_data = {
                    'access_token': self.ACCESS_TOKEN,
                    'error': None,
                    'expires_in': 3600,
                    'scope': self.SCOPE,
                    'token_type': 'Bearer'
                }
                self.send_response(200)
                self.end_headers()
                self.wfile.write(json.dumps(response_data).encode())
            else:
                self.send_response(403)
                self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()


if __name__ == '__main__':
    try:
        httpd = HTTPServer(('localhost', PORT), MockServerRequestHandler)
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.shutdown()
        print()