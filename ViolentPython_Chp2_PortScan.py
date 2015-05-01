__author__ = 'jinksPadlock'
import optparse
from socket import *
from threading import *


screenLock = Semaphore(value=1)


def conn_scan(target_host, target_port):
    try:
        conn_socket = socket(AF_INET, SOCK_STREAM)
        conn_socket.connect((target_host, target_port))
        conn_socket.send('Blergh_I_Am_A_Scan\r\n')
        results = conn_socket.recv(100)
        screenLock.acquire()
        print('[+] %d/tcp open' % target_port)
        print('[+] ' + str(results))
    except:
        screenLock.acquire()
        print('[-] %d/tcp closed' % target_port)
    finally:
        screenLock.release()
        conn_socket.close()


def port_scan(target_host, target_port):
    try:
        target_ip = gethostbyname(target_host)
    except:
        print("[-] Cannot resolve '%s': Unknown host" %target_host)
        return

    try:
        target_name = gethostbyaddr(target_ip)
        print('\n[+] Scan Results for: ' + target_name[0])
    except:
        print('\n[+] Scan Results for: ' + target_ip)

    setdefaulttimeout(1)
    for tgtPort in target_port:
        t = Thread(target=conn_scan, args=(target_host, int(tgtPort)))
        t.start()


def main():
    parser = optparse.OptionParser('usage %prog -H <target host> -p <target port>')
    parser.add_option('-H', dest='target_host', type='string', help='specify target host')
    parser.add_option('-p', dest='target_ports', type='string', help='specify target ports')
    (options, args) = parser.parse_args()
    target_host = options.target_host
    target_ports = options.target_port
    if target_host is None | target_ports is None:
        print(parser.usage)
        exit(0)

    target_host = options.tgtHost
    target_ports = str(options.tgtPort).split(',')

    if (target_host is None) | (target_ports[0] is None):
        print(parser.usage)
        exit(0)

    port_scan(target_host, target_ports)


if __name__ == '__main__':
    main()