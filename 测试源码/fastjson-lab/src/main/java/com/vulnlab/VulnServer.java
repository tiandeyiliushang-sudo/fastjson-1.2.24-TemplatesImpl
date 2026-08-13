package com.vulnlab;

import com.alibaba.fastjson.JSON;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import com.alibaba.fastjson.parser.Feature;      // ← 新增
import com.alibaba.fastjson.parser.ParserConfig;  // ← 新增

import java.io.*;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;

/**
 * FastJSON 1.2.24 漏洞靶场
 * 
 * 功能点：
 *   POST /api/user/info  - 用户信息查询接口（接收 JSON，用 FastJSON 解析）
 *   GET  /               - 首页
 * 
 * 漏洞点：
 *   FastJSON 1.2.24 默认开启 autoType
 *   攻击者可通过 @type 指定任意类，触发 TemplatesImpl 链实现 RCE
 */
public class VulnServer {

    private static final int PORT = 8888;

    public static void main(String[] args) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(PORT), 0);
        
        // 访问首页，交给IndexHandler()处理
        server.createContext("/", new IndexHandler());
        
        // 漏洞接口：用户信息查询，交给UserInfoHandler()处理
        server.createContext("/api/user/info", new UserInfoHandler());
        
        server.setExecutor(null);
        server.start();
        
        System.out.println("===========================================");
        System.out.println("  FastJSON 1.2.24 漏洞靶场已启动");
        System.out.println("  监听端口: " + PORT);
        System.out.println("===========================================");
        System.out.println();
        System.out.println("  功能接口:");
        System.out.println("    GET  http://localhost:" + PORT + "/");
        System.out.println("    POST http://localhost:" + PORT + "/api/user/info");
        System.out.println();
        System.out.println("  正常用法:");
        System.out.println("    curl -X POST http://localhost:" + PORT + "/api/user/info \\");
        System.out.println("      -H 'Content-Type: application/json' \\");
        System.out.println("      -d '{\"name\":\"张三\",\"age\":18}'");
        System.out.println();
        System.out.println("  漏洞利用（FastJSON 1.2.24 @type）:");
        System.out.println("    构造恶意 JSON payload 触发 TemplatesImpl 链");
        System.out.println();
    }

    /**
     * 首页，get的，不是漏洞触发点
     */
    static class IndexHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String html = "<!DOCTYPE html>\n" +
                "<html><head><title>FastJSON 漏洞靶场</title></head>\n" +
                "<body>\n" +
                "<h1>FastJSON 1.2.24 漏洞靶场</h1>\n" +
                "<p>功能接口: POST /api/user/info</p>\n" +
                "<p>接收 JSON 格式的用户信息</p>\n" +
                "<h2>正常请求示例:</h2>\n" +
                "<pre>curl -X POST http://localhost:8888/api/user/info \\\n" +
                "  -H 'Content-Type: application/json' \\\n" +
                "  -d '{\"@type\":\"com.vulnlab.User\",\"name\":\"张三\",\"age\":18}'</pre>\n" +
                "<h2>靶场信息:</h2>\n" +
                "<ul>\n" +
                "<li>FastJSON 版本: 1.2.24</li>\n" +
                "<li>漏洞类型: 反序列化 RCE</li>\n" +
                "<li>CVE: CVE-2017-18349</li>\n" +
                "</ul>\n" +
                "</body></html>";
            
            exchange.getResponseHeaders().set("Content-Type", "text/html; charset=utf-8");
            exchange.sendResponseHeaders(200, html.getBytes(StandardCharsets.UTF_8).length);
            OutputStream os = exchange.getResponseBody();
            os.write(html.getBytes(StandardCharsets.UTF_8));
            os.close();
        }
    }

    /**
     * 用户信息接口 - 漏洞点
     * 
     * 接收 JSON 格式的用户信息，使用 FastJSON 解析
     * FastJSON 1.2.24 默认开启 autoType，可被利用
     */
    static class UserInfoHandler implements HttpHandler {
        @Override
        //对get返回405，不支持
        public void handle(HttpExchange exchange) throws IOException {
            if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
                String msg = "{\"error\":\"请使用 POST 方法\"}";
                exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
                exchange.sendResponseHeaders(405, msg.getBytes(StandardCharsets.UTF_8).length);
                OutputStream os = exchange.getResponseBody();
                os.write(msg.getBytes(StandardCharsets.UTF_8));
                os.close();
                return;
            }

            // 读取请求体
            InputStream is = exchange.getRequestBody();
            BufferedReader reader = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                sb.append(line);
            }
            String requestBody = sb.toString();

            System.out.println("[*] 收到请求: " + requestBody);

            String response;
            try {
                // ========== 漏洞点：使用 FastJSON 解析用户输入 ==========
                // FastJSON 1.2.24 默认开启 autoType
                // 攻击者可通过 @type 指定任意类
                // 必须传 Feature.SupportNonPublicField 才能设置 private 字段（_bytecodes）
                //Object result = JSON.parseObject(requestBody, Object.class, new ParserConfig(), Feature.SupportNonPublicField);
                Object result = JSON.parseObject(requestBody,Feature.SupportNonPublicField);
                // ==========================================================
                
                response = "{\"code\":200,\"msg\":\"解析成功\",\"data\":" + result.toString() + "}";
                System.out.println("[+] 解析成功: " + result.toString());
                
            } catch (Exception e) {
                response = "{\"code\":500,\"msg\":\"解析失败: " + e.getMessage() + "\"}";
                System.out.println("[-] 解析失败: " + e.getMessage());
            }

            exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
            exchange.sendResponseHeaders(200, response.getBytes(StandardCharsets.UTF_8).length);
            OutputStream os = exchange.getResponseBody();
            os.write(response.getBytes(StandardCharsets.UTF_8));
            os.close();
        }
    }
}
