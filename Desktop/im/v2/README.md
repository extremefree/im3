# IPv6 P2P 聊天系统 v3

基于 IPv6 的即时通讯系统，服务端和客户端核心逻辑使用 **x86-64 汇编 (NASM)** 编写，跨平台抽象层和用户认证模块使用 **C** 编写。

## 功能特性

- **IPv6 通信** — 原生 IPv6 套接字，支持本地 (`::1`) 和公网 IPv6 地址
- **用户认证** — LOGIN 登录 + /REGISTER 注册，凭据 XOR 加密存储
- **每客户端缓冲区** — 环形缓冲区 + 行提取，彻底解决 TCP 粘包问题
- **跨平台抽象** — calling.inc 宏处理 System V / Win64 调用约定差异，platform.c/h 统一套接字和 I/O 接口
- **交互式/自动登录** — 客户端支持命令行参数自动登录，也支持运行后交互输入

## 编译

### Linux / WSL2

依赖：`nasm`, `gcc`, `make`

```bash
cd v3
make
```

编译产物：
- `server` — 服务端
- `client` — 客户端

> 注意：如果在 WSL2 中编译，二进制文件需复制到 `/tmp/` 执行（Windows 文件系统权限问题）：
> ```bash
> cp server /tmp/server3
> cp client /tmp/client3
> ```

## 使用方法

### 1. 启动服务端

```bash
./server
```

输出：
```
[server] listening on [::]:9000
```

服务端监听 `[::]:9000`（所有 IPv6 地址，端口 9000）。

### 2. 启动客户端

客户端支持三种模式：

#### 模式一：自动登录（三个参数）

```bash
./client <IPv6地址> <用户名> <密码>
```

示例：
```bash
./client ::1 alice alice123
./client 2408:8207:4821:1311:c038:c41e:3f76:8cea bob bob456
```

连接后自动发送登录请求，无需手动操作。登录成功后直接进入聊天。

#### 模式二：交互式登录（一个参数，仅地址）

```bash
./client <IPv6地址>
```

示例：
```bash
./client ::1
```

连接后会显示：
```
[cli] connecting...
[cli] connected
Welcome! Please login: LOGIN name:pass
```

此时输入 `用户名:密码` 并回车：
```
alice:alice123
OK logged in
```

登录成功后输入的每一行都会作为消息广播给其他在线用户。

#### 模式三：默认地址交互式登录（无参数）

```bash
./client
```

使用内置默认地址 `2408:8207:4821:1311:c038:c41e:3f76:8cea` 连接，然后交互式登录。

### 3. 发送消息

登录成功后，输入任意文本并回车即可发送。消息会以 `[用户名] 消息内容` 的格式广播给所有其他在线用户。

示例会话：

```
$ ./client ::1 alice alice123
[cli] connecting...
[cli] connected
Welcome! Please login: LOGIN name:pass
OK logged in
hello everyone
[bob] hi alice!
```

### 4. 注册新用户

连接后在登录提示下发送 `/REGISTER` 命令：

```
/REGISTER 新用户名:密码
```

示例：
```
Welcome! Please login: LOGIN name:pass
/REGISTER charlie:mypass123
OK logged in
```

注册成功后自动登录。

## 预置用户

系统首次启动时自动创建两个用户（保存在 `/tmp/im_users.dat`，XOR 加密）：

| 用户名 | 密码 |
|--------|------|
| alice | alice123 |
| bob | bob456 |

## 跨机器测试（公网 IPv6）

1. 在机器 A 上启动服务端：
   ```bash
   ./server
   ```

2. 确认机器 A 的公网 IPv6 地址：
   ```bash
   ip -6 addr | grep global
   ```

3. 确保 Windows 防火墙允许端口 9000 的入站 IPv6 连接（PowerShell 管理员）：
   ```powershell
   New-NetFirewallRule -DisplayName "Chat v3" -Direction Inbound -Protocol TCP -LocalPort 9000 -Action Allow
   ```

4. 在机器 B 上连接：
   ```bash
   ./client <机器A的公网IPv6地址> alice alice123
   ```

## 项目结构

```
v3/
├── calling.inc          # 跨平台调用约定宏 (System V / Win64)
├── platform.h           # 跨平台 OS 抽象接口
├── platform.c           # 跨平台实现 (socket/select/I/O)
├── buffer.asm           # 每客户端环形缓冲区 + 行提取
├── net_utils.asm        # 字符串/内存/XOR 加密工具函数
├── auth.c               # 用户认证、会话管理、加密文件读写
├── server_main.asm      # 服务端主逻辑 (select 循环/登录/广播)
├── client_main.asm      # 客户端主逻辑 (交互式/自动登录)
└── Makefile             # 构建脚本
```

## 端口

| 协议 | 端口 | 说明 |
|------|------|------|
| TCP/IPv6 | 9000 | 聊天服务端口 |

## 快速测试（本地）

打开三个终端：

```bash
# 终端 1 — 启动服务端
./server

# 终端 2 — alice 登录
./client ::1 alice alice123

# 终端 3 — bob 登录
./client ::1 bob bob456
```

在任意客户端输入文字，另一个客户端会收到 `[用户名] 消息` 格式的广播。
