#### **1. 功能描述**
radius服务，包括认证和计费，具体如下：
1. 程序参数包括 nas接入点ip，支持多个ip或者ip段，radius共享密钥
2. 支持完整的pap，chap和mac认证
3. 支持认证处理，并对接外部数据库redis，用户名，明文密码预置在redis中
4. 支持计费处理，并对接外部Kafka，计费数据格式为json
5. 支持日志记录，日志格式为json，日志存储在本地文件中
6. 支持日志轮转，日志文件大小超过1GB时自动切割
7. 支持日志级别可调，默认级别为info
8. 具备高性能，能够处理高并发请求
9. 具备完善的异常处理机制，能够记录错误日志并进行适当的错误响应
10. 支持配置文件，能够通过配置文件调整服务参数

#### **2. redis用户数据举例**
数据都在db0中，两种存储形式：
1. 用户名和密码存储在redis中，格式为：`user:username password`
2. mac地址和认证标志位存储在redis中，格式为：`mac:mac_address username`
```
user:18694960921 123456
user:admin 123456
mac:c69cd2ad608c 18694960921       # C69CD2AD608C为mac地址，自动移除: 和 - 符号
```
来自MAC认证的请求会去查mac地址是否存在，成功则返回认证成功，失败则返回认证失败。
来自PAP/CHAP认证的请求会去查用户名和密码是否匹配，成功则返回认证成功，失败则返回认证失败。

#### **3. 计费json数据举例**

| **字段名**          | **类型** | **必填** | **描述**                          | **示例值**                              |
|----------------------|----------|----------|-----------------------------------|----------------------------------------|
| `event_type`         | string   | ✔️       | 事件类型（Start/Interim-Update/Stop） | `"Start"`                             |
| `timestamp`          | integer  | ✔️       | Unix 时间戳（秒级）               | `1739234658`                          |
| `event_timestamp`    | string   | ✔️       | ISO 8601 格式时间（UTC）          | `"2025-02-09T18:35:02Z"`              |
| `user_name`          | string   | ✔️       | 用户名                            | `"xiaxie"`                            |
| `nas_identifier`     | string   | ✔️       | NAS 设备标识                      | `"H3C"`                               |
| `nas_ip`             | string   | ✔️       | NAS IP 地址                       | `"192.168.1.50"`                      |
| `acct_session_id`    | string   | ✔️       | 会话唯一 ID                       | `"000000042025020910350200000b0308102414"` |
| `framed_ip`              | string   | ✔️       | 用户分配的 IP 地址                | `"192.168.200.108"`                   |
| `calling_station_id`     | string   | ✔️       | 用户 MAC 地址                     | `"C6-9C-D2-AD-60-8C"`                 |
| `called_station_id`      | string   | ✔️       | 接入点标识                        | `"94-3B-B0-2E-C3-B0:H3C-NAC-Dot1X"`   |
| `nas_port`               | integer  | ✔️       | NAS 端口号                        | `16777416`                             |
| `nas_port_type`          | string   | ✔️       | 端口类型                          | `"Wireless-802.11"`                    |


#### **4. 认证json数据举例**

| **字段名**          | **类型** | **必填** | **描述**                          | **示例值**                              |
|----------------------|----------|----------|-----------------------------------|----------------------------------------|
| `timestamp`          | integer  | ✔️       | Unix 时间戳（秒级）               | `1739234658`                          |
| `user_name`          | string   | ✔️       | 用户名                            | `"xiaxie"`                            |
| `nas_ip`             | string   | ✔️       | NAS IP 地址                       | `"192.168.1.50"`                      |
| `framed_ip`              | string   | ✔️       | 用户分配的 IP 地址                | `"192.168.200.108"`                   |
| `calling_station_id`     | string   | ✔️       | 用户 MAC 地址                     | `"C6-9C-D2-AD-60-8C"`                 |
| `success`               | bool  | ✔️       | 认证成功                        | `false`                             |
| `reason`          | string   | ✔️       | 失败原因，成功为空                          | `"Invalid credentials"`                    |
