#!/usr/bin/python3

"""
Name: cuddlyclara
Website: cuddlyclara.de
Source: https://github.com/cnszlijz/SimpleDoHServer
Description: Very simple DoH server based on Python 3, which passes the client IP via ECS.
"""

import json
import base64
import logging
import ipaddress
import http.server
import socketserver
import urllib.parse
import dns.message
import dns.edns
import dns.query
import sys
import signal

def handle_sigterm(signum, frame):
    print("signal SIGTERM received, exiting...")
    logging.warning("signal SIGTERM received, exiting...")
    raise KeyboardInterrupt

def is_valid_ipv4(ip_str):
    try:
        ipaddress.IPv4Address(ip_str)
        return True
    except ipaddress.AddressValueError:
        return False

def requestDNSAnswer(query, clientip=''):
    # Parse the DNS query message from wire format
    request = dns.message.from_wire(query)

    # Log DNS query details: type, domain, and client IP if available
    if len(request.question) > 0:
        question = request.question[0]
        logging.debug(f'query {dns.rdatatype.to_text(question.rdtype)} {question.name.to_text()} from {clientip}')

    # Include EDNS with ECS option from client IP address if client IP address is valid
    '''if is_valid_ipv4(clientip):
        ecs = dns.edns.ECSOption.from_text(clientip + '/32')
        request.use_edns(edns=True, options=[ecs])
    else:
        logging.debug(f'client IP {clientip} not valid using server IP for request')'''

    # Send the query
    try:
        #response, fallback_used = dns.query.udp_with_fallback(request, dnsserver, timeout)
        response = dns.query.tcp(request, dnsserver, timeout)
    except dns.exception.Timeout:
        logging.info(f'out of time query {dns.rdatatype.to_text(question.rdtype)} {question.name.to_text()}')
        return dns.message.make_response(request).to_wire()

    # Log a warning if fallback to TCP was necessary
    #if fallback_used:
        #logging.warning('fallback to TCP required')

    # Return the DNS response
    return response.to_wire()

def main():
    # Enable address reuse to prevent 'Address already in use' error
    socketserver.TCPServer.allow_reuse_address = True
    signal.signal(signal.SIGTERM, handle_sigterm)

    # Create the DoH server
    #with socketserver.TCPServer((host, port), DohHandler) as httpd:
    with http.server.ThreadingHTTPServer((host, port), DohHandler) as httpd:
        try:
            print(f'Serving DoH on {host}:{port} using DNS server {dnsserver}')
            logging.warning('Service start')
            with open('httpd.log', 'a', buffering=1) as f:
                sys.stdout = f
                httpd.serve_forever()
        except KeyboardInterrupt:
            logging.warning('KeyboardInterrupt received, shutting down the server...')
            httpd.shutdown()

class DohHandler(http.server.BaseHTTPRequestHandler):
    def sendErrorResponse(self, code, e):
        error_data = {
            'error_code': code,
            'error_type': type(e).__name__,
            'error_message': str(e)
        }
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps({'error': error_data}).encode('utf-8'))

    def sendDoHResponse(self, dns_answer):
        try:
            self.send_response(200)
            self.send_header('Content-Type', 'application/dns-message')
            self.end_headers()
            self.wfile.write(dns_answer)
        except socket.error:#.ConnectionAbortedError:
            pass

    def do_GET(self):
        try:
            # Parse the dns query parameter
            query = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            dns_query = base64.b64decode(query['dns'][0])
        except Exception as e:
            # Provides a 'Bad Request' response in case of a parsing error
            self.sendErrorResponse(400, e)
            logging.info(f'malformed GET request: {str(e)}')
            return#raise

        try:
            dns_answer = requestDNSAnswer(dns_query, self.headers[realipheader])
        except Exception as e:
            # Provides a 'Internal Server Error' response in case of a DNS resolution error
            self.sendErrorResponse(500, e)
            logging.error(e)
            raise

        # Respond with DoH response
        self.sendDoHResponse(dns_answer)

    def do_POST(self):
        try:
            # Parse the input stream
            content_length = int(self.headers['Content-Length'])
            dns_query = self.rfile.read(content_length)
        except Exception as e:
            # Provides a 'Bad Request' response in case of a parsing error
            self.sendErrorResponse(400, e)
            logging.info(f'malformed POST request: {str(e)}')
            return#raise

        try:
            dns_answer = requestDNSAnswer(dns_query, self.headers[realipheader])
        except Exception as e:
            # Provides a 'Internal Server Error' response in case of a DNS resolution error
            self.sendErrorResponse(500, e)
            logging.error(e)
            raise

        # Respond with DoH response
        self.sendDoHResponse(dns_answer)

if __name__ == '__main__':
    # Set the LogLevel to logging.WARNING or logging.ERROR to suppress the output of DNS requests
    logging.basicConfig(filename='dns-server.log',
                        filemode='a',
                        format='[%(asctime)s] [%(name)s/%(levelname)-4s]: %(message)s',
                        level=logging.WARNING)

    # Set the server address, port, dns server, dns request timeout (in seconds) and the real ip header
    host = '127.0.0.1'
    port = 53533
    dnsserver = '127.0.0.1'
    timeout = 4
    #if timeout is larger than 10s, Chrome will close its https connection, which will cause 499 in nginx and net::ERR_DNS_TIMED_OUT in Chrome
    #if timeout it 10s, Chrome will receive HTTP 500 and result in net::ERR_DNS_MALFORMED_RESPONSE
    realipheader = 'X-Forwarded-For'

    # Call the main function
    main()
