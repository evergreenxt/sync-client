#
# Copyright (c) 2012 Citrix Systems, Inc.
# 
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#

"""Test module for httpclient"""

from multiprocessing import Process, Queue
from wsgiref.simple_server import make_server
from socket import error
from json import dumps
from copy import deepcopy
from sync_client.client import ServerError, HTTPServer, make_call
from requests import TooManyRedirects, ConnectionError

SERVER_ADDR = '127.0.0.1'
SERVER_PORT = 8805

def run_server(queue, wsgi_application):
    """Run a WSGI server"""
    port = SERVER_PORT
    while 1:
        try:
            server = make_server('', port, wsgi_application)
        except error:
            port += 1
        else:
            break
    queue.put(port)
    server.serve_forever()

def start_server(wsgi_application):
    """Start test HTTP server"""
    queue = Queue()
    process = Process(target=run_server, args=(queue, wsgi_application))    
    process.start()
    port = queue.get()
    return (process, queue), port

def close_server(server):
    """Shut down test HTTP server"""
    server[0].terminate()

def make_url(address, port):
    """Return a URL string"""
    return "http://%s:%d/" % (address, port)

def test_hello_fail_server_error():
    """test hello failure on server side"""
    def wsgi_app(_):
        """Handle WSGI request"""
        return 1 / 0 # internal server error

    server, port = start_server(wsgi_app)
    base_url = make_url(SERVER_ADDR, port)
    try:
        client = HTTPServer(base_url)
        make_call(client.fetch, 'hello', client_version=1)
    except ServerError, ex:
        assert 'status 500' in ex.message
    else:
        raise Exception("Expected a ServerError to be thrown")
    finally:
        close_server(server)

def test_hello_fail_too_many_redirects():
    """test hello failure due to too many redirects"""
    url = make_url(SERVER_ADDR, SERVER_PORT)
    def wsgi_app(_, start_response):
        """Handle WSGI request"""
        start_response("301 Moved", [('location', url)]) #redirect to same URL
        return ["301 Moved"]

    server, port = start_server(wsgi_app)
    try:
        assert(port == SERVER_PORT) #rare that server gets a different port
        client = HTTPServer(url)
        make_call(client.fetch, 'hello', client_version=1)
    except TooManyRedirects:
        pass
    else:
        raise Exception("Expected TooManyRedirects to be thrown")
    finally:
        close_server(server)

def test_hello_fail_connection_error():
    """test hello failure due to connection error"""
    def wsgi_app(_):
        """Handle WSGI request"""
        pass

    server, port = start_server(wsgi_app)
    try:
        url = make_url(SERVER_ADDR, port+1) # no HTTP server on port+1
        client = HTTPServer(url)
        make_call(client.fetch, 'hello', client_version=1)
    except ConnectionError:
        pass
    else:
        raise Exception("Expected ConnectionError to be thrown")
    finally:
        close_server(server)

def test_hello():
    """test hello rpc"""
    def wsgi_app(env, start_response):
        """Handle WSGI request"""
        assert(env['PATH_INFO'] == '/hello')
        start_response('200 OK', [('content-type', 'application/json')])
        response = {'server_version': 1}
        return [dumps(response)]

    server, port = start_server(wsgi_app)
    try:
        client = HTTPServer(make_url(SERVER_ADDR, port))
        result = make_call(client.fetch, 'hello', client_version=1)
    finally:
        close_server(server)
    assert (result != None)
    server_version = result['server_version']
    assert (server_version == 1)

def test_get_disk_info():
    """test get_disk_info rpc"""
    expected_info = {'diskuuid': 1234,
                     'checksum': 'testchecksum',
                     'encryption_key': 'testencryptionkey'}
    def wsgi_app(env, start_response):
        """Handle WSGI request"""
        assert(env['PATH_INFO'] == '/get_disk_info')
        start_response('200 OK', [('content-type', 'application/json')])
        response = deepcopy(expected_info)
        return [dumps(response)]

    server, port = start_server(wsgi_app)
    try:
        client = HTTPServer(make_url(SERVER_ADDR, port))
        result = make_call(client.fetch, 'get_disk_info', diskuuid=1234)
    finally:
        close_server(server)
    assert (result != None)
    assert (result == expected_info)

def test_get_state():
    """test get_state rpc"""
    expected_state = {'vms':[
                      {'name':'win7', 'vmuuid':1, 'disks':[
                              {'diskuuid':0, 'name':'win7boot',
                               'size':40*1000*1000*1000}]},
                      {'name':'xp', 'vmuuid':2, 'disks':[]}]}

    def wsgi_app(env, start_response):
        """Handle WSGI request"""
        assert(env['PATH_INFO'] == '/get_state')
        start_response('200 OK', [('content-type', 'application/json')])
        response = deepcopy(expected_state)
        return [dumps(response)]

    server, port = start_server(wsgi_app)
    try:
        client = HTTPServer(make_url(SERVER_ADDR, port))
        result = make_call(client.fetch, 'get_state')
    finally:
        close_server(server)
    assert (result != None)
    assert (result == expected_state)


if __name__ == "__main__":
    test_get_state()

