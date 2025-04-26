#!/usr/bin/env python3
# -*- coding: utf-8 -*- # 明确指定UTF-8编码，支持中文注释

import requests
from bs4 import BeautifulSoup
import re
import argparse
import sys
import time
import json
from urllib.parse import urlparse, urljoin
import colorama
from colorama import Fore, Style
from concurrent.futures import ThreadPoolExecutor
import warnings
from requests.packages.urllib3.exceptions import InsecureRequestWarning
# import tabulate # 移除tabulate库的导入
import pandas as pd # 导入pandas库

# --- 常量定义 ---
DEFAULT_TIMEOUT = 15 # 默认请求超时时间（秒）
DEFAULT_MAX_WORKERS = 10 # 默认并发工作线程数
HTTP_OK = 200
HTTP_CREATED = 201
HTTP_NO_CONTENT = 204
HTTP_UNAUTHORIZED = 401
HTTP_FORBIDDEN = 403
HTTP_NOT_FOUND = 404

# 需要检查的常见API路径列表
API_PATHS = [
    '/api', '/api/v1', '/api/v2', '/rest', '/graphql',
    '/data', '/service', '/services', '/wp-json', '/_api',
    '/api/users', '/api/products' # 示例API路径，可根据需要添加更多
]

# --- 初始化 ---
colorama.init(autoreset=True) # 初始化colorama
warnings.simplefilter('ignore', InsecureRequestWarning) # 禁用SSL证书验证警告

# --- 辅助函数：用于模式匹配 ---
def find_matches(patterns_dict, content, limit_per_pattern=3):
    """
    在指定内容中搜索字典定义的模式。

    Args:
        patterns_dict (dict): 字典，键是类别，值是已编译的正则表达式模式列表。
        content (str): 要搜索的文本内容。
        limit_per_pattern (int): 每个模式类别返回的最大匹配项数。

    Returns:
        dict: 结果字典，包含每个类别的 'found' (布尔值) 状态和 'evidence' (列表) 证据。
    """
    results = {}
    if not content:
        return results

    for category, compiled_patterns in patterns_dict.items():
        found_category = False
        evidence = []
        for pattern in compiled_patterns:
            try:
                # finditer 返回迭代器，对大文件更高效
                for m in pattern.finditer(content):
                    match = m.group(0)
                    if match not in evidence: # 避免重复证据
                         evidence.append(match)
                         if len(evidence) >= limit_per_pattern:
                            break
                if evidence:
                    found_category = True
                if len(evidence) >= limit_per_pattern: # 提前退出模式循环
                    break
            except Exception as e:
                 # print(f"{Fore.YELLOW}模式匹配错误: {e}") # 调试用，避免在生产环境打印过多
                 pass
        results[category] = {
            "found": found_category,
            "evidence": evidence
        }
    return results

class WebAppDetector:
    """
    Web应用检测器类，用于识别网站使用的技术栈。
    """
    def __init__(self, timeout=DEFAULT_TIMEOUT, max_workers=DEFAULT_MAX_WORKERS):
        """初始化Web应用检测器"""
        self.timeout = timeout
        self.max_workers = max_workers

        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
        }

        # --- 预编译正则表达式模式 ---
        # 增加了更多模式，提高了捕获通用库的能力
        vue_patterns_raw = {
            "Vue实例初始化": [r'new\s+Vue\s*\(', r'Vue\.createApp\s*\(', r'createApp\s*\(', r'const\s+app\s*=\s*createApp\s*\(', r'var\s+app\s*=\s*new\s+Vue\s*\('],
            "Vue指令": [r'v-(if|for|bind|model|on|show|html|text|else|else-if|cloak|pre|once|slot)', r'@(click|change|input|submit|keyup|keydown)', r':(class|style|src|href|disabled|value)'],
            "Vue组件结构": [r'<[\w-]+\s+(?:[^>]*\s+)?(?:v-[\w-]+|:[\w-]+|@[\w-]+)=', r'<(component|transition|keep-alive|teleport|suspense)[^>]*>', r'<slot[^>]*>', r'\.component\s*\(\s*[\'"][^\'"]+[\'"]'],
            "Vue库引用": [
                r'vue(\.[min])?\.js', r'vue(@[\d\.]+/dist)', r'vue(-router|-resource)?(@[\d\.]+)?', r'vuex(@[\d\.]+)?',
                r'vue\.runtime(\.[min])?\.js', r'vue\.esm(\.[min])?\.js', r'\/vue\/[\d\.]+\/vue' # 增加CDN等常见路径模式
            ],
            "Vue UI框架": [
                r'vuetify(\.[min])?\.js', r'<v-(app|card|btn|dialog|navigation-drawer)',
                r'element-ui', r'<el-(button|table|form|input|select|dialog)',
                r'quasar', r'bootstrap-vue', r'vue-material', r'vuetify',
                r'ant-design-vue', r'<a-button', r'iview', r'<i-button',
                r'vant' # 增加移动端Vue UI
            ],
            "Vue生态组件": [r'_nuxt/', r'/__nuxt/', r'nuxt\.(js|min\.js)', r'vue-router', r'pinia', r'vuex', r'nuxtjs', r'@vue/'] # 增加@vue/前缀
        }
        spa_patterns_raw = {
            "API调用模式": [
                r'\.(get|post|put|delete|ajax|fetch)\s*\(\s*([\'"](https?:)?//)', r'axios\.(get|post|put|delete)',
                r'api\/v\d+\/', r'\/rest\/v\d+\/', r'/graphql',
                r'fetch\s*\(\s*[\'"]', r'XMLHttpRequest\s*\(', r'\$.ajax\s*\('
            ],
            "前端路由模式": [
                r'mode\s*:\s*[\'"]history[\'"]', r'createRouter', r'Router\.prototype',
                r'ReactRouter', r'BrowserRouter', r'RouterProvider', r'#\/[a-zA-Z0-9]',
                r'vue-router', r'react-router-dom', r'angular-route'
            ],
            "数据状态管理": [
                r'createStore', r'new Vuex\.Store', r'useReducer', r'useState',
                r'ReactRedux', r'connect\(', r'mapState', r'mapGetters', r'createSlice',
                r'pinia', r'redux', r'MobX', r'Zustand'
            ],
            "前端构建标记": [
                r'webpackJsonp', r'__NEXT_DATA__', r'window\.__NUXT__', r'window\.__INITIAL_STATE__',
                r'chunked', r'"buildId":', r'react-dom', r'runtime~main\.[a-z0-9]+\.js',
                r'chunk\.[a-z0-9]+\.js', r'vite', r'_next/', r'/_next/', r'_gatsby/', r'/_gatsby/',
                r'static/js/', r'bundle\.js', r'main\.js', r'vendor\.js' # 增加common/vendor
            ],
             "通用前端库": [
                r'lodash', r'moment\.js', r'underscore\.js', r'rxjs', r'axios', 'fetch',
                r'bootstrap(\.[min])?\.js', r'tailwind(\.[min])?\.css', r'materialize(\.[min])?\.js',
                r'animate\.css', r'fontawesome', r'slick\.js', r'owl\.carousel\.js',
                r'jquery(\.min)?\.js', r'jquery-\d+(\.\d+){1,2}(\.min)?\.js' # 将jquery也归入通用库
            ]
        }
        frontend_frameworks_raw = {
            "React": [
                r'react(\.production)?(\.min)?\.js', r'react-dom', r'_reactListening',
                r'__REACT_DEVTOOLS_GLOBAL_HOOK__', r'_reactRootContainer', r'ReactDOM\.render',
                r'createRoot', r'useState', r'useEffect', r'data-reactroot', r'data-reactid',
                r'react\.createElement', r'<div\s+id=[\'"]?root[\'"]?>', r'react-router-dom'
            ],
            "Angular": [
                r'ng-version', r'angular(\.min)?\.js', r'ng-app', r'ng-controller',
                r'ng-model', r'ngRepeat', r'"ANGULAR_APP_INITIALIZER"', r'angular\.bootstrap',
                r'zone\.js', r'polyfill', r'data-ng-app', r'ng-binding'
            ],
            # jQuery 已经移到 通用前端库
            "Svelte": [r'svelte(\.[min])?\.js', r'__svelte'],
            "Ember.js": [r'ember(\.[min])?\.js', r'Ember\.VERSION']
        }

        self.compiled_vue_patterns = {k: [re.compile(p, re.IGNORECASE) for p in v] for k, v in vue_patterns_raw.items()}
        self.compiled_spa_patterns = {k: [re.compile(p, re.IGNORECASE) for p in v] for k, v in spa_patterns_raw.items()}
        self.compiled_frontend_patterns = {k: [re.compile(p, re.IGNORECASE) for p in v] for k, v in frontend_frameworks_raw.items()}

        # 后端框架检测特征
        self.backend_frameworks_signatures = {
            "Spring": ["X-Application-Context", "JSESSIONID", "org.springframework", "Set-Cookie: SPRING_SECURITY_REMEMBER_ME_COOKIE", "Server: Jetty", "Server: Tomcat"],
            "Django": ["csrftoken", "Set-Cookie: sessionid", "X-Frame-Options: SAMEORIGIN", "Server: gunicorn", "Server: uwsgi"],
            "Laravel": ["laravel_session", "X-XSRF-TOKEN", "XSRF-TOKEN", "Set-Cookie: laravel_session", "Server: nginx", "Server: Apache"],
            "Express": ["X-Powered-By: Express", "Set-Cookie: connect.sid"],
            "Rails": ["Set-Cookie: _rails_session", "X-Request-Id", "X-Runtime", "Server: Passenger", "Server: Puma", "Server: Unicorn"],
            "ASP.NET": ["Set-Cookie: ASP.NET_SessionId", "X-AspNet-Version", "X-AspNetMvc-Version", "__VIEWSTATE", "X-Powered-By: ASP.NET", "Server: IIS"],
            "Flask": ["Set-Cookie: session=", "Server: Werkzeug/"],
            "PHP": ["X-Powered-By: PHP", "Set-Cookie: PHPSESSID"],
            "Node.js": ["X-Powered-By: Express", "Server: Node.js", "Server: express"],
            "Python": ["Server: gunicorn", "Server: uwsgi", "Server: Werkzeug/"], # Python常用的服务器
            "Java": ["Server: Jetty", "Server: Tomcat", "Server: WildFly", "Server: Undertow", "JSESSIONID"], # Java常用的服务器和cookie
            "Ruby": ["Server: Passenger", "Server: Puma", "Server: Unicorn"],
            "Go": ["Server: Go", "Server: Caddy"], # 增加Go语言的常见服务器
            "Nginx": ["Server: nginx"], # 常见Web服务器作为提示
            "Apache": ["Server: Apache"] # 常见Web服务器作为提示
        }


    def _normalize_url(self, url):
        """规范化URL，如果缺少协议方案，优先尝试添加 'https://'。"""
        parsed = urlparse(url)
        if not parsed.scheme:
            https_url = 'https://' + url
            try:
                # 使用 HEAD 请求快速检查HTTPS是否可用
                requests.head(https_url, timeout=self.timeout / 4, verify=False, allow_redirects=True, headers=self.headers) # 缩短超时时间
                return https_url
            except requests.exceptions.RequestException:
                return 'http://' + url
        return url

    def fetch_url(self, url, method='GET', allow_redirects=True):
        """
        获取URL内容或执行HEAD请求，处理URL规范化和基本的请求错误。
        增加了 method 参数以支持 HEAD 请求。
        """
        try:
            normalized_url = self._normalize_url(url)
            if method.upper() == 'HEAD':
                 response = requests.head(
                     normalized_url,
                     headers=self.headers,
                     timeout=self.timeout / 2, # HEAD请求超时减半
                     allow_redirects=allow_redirects,
                     verify=False
                 )
            else:
                response = requests.get(
                    normalized_url,
                    headers=self.headers,
                    timeout=self.timeout,
                    allow_redirects=allow_redirects,
                    verify=False
                )
            response.raise_for_status() # 检查HTTP状态码是否表示成功
            return response
        except requests.exceptions.Timeout:
            return {'error': '请求超时', 'url': url}
        except requests.exceptions.ConnectionError:
            return {'error': f'连接错误: {urlparse(url).netloc}', 'url': url}
        except requests.exceptions.HTTPError as e:
             return {'error': f'HTTP错误: {e.response.status_code} {e.response.reason}', 'status_code': e.response.status_code, 'url': getattr(e.response, 'url', url)}
        except requests.exceptions.RequestException as e:
            return {'error': f'请求失败: {str(e)}', 'url': url}

    def check_api_endpoints(self, base_url):
        """使用 HEAD 请求并发检查常见的 API 端点是否存在。"""
        api_results = {}
        parsed_base = urlparse(base_url)
        scheme = parsed_base.scheme
        domain = parsed_base.netloc

        if not scheme or not domain:
             return {"error": "无效的基础URL，无法检查API"}

        # 如果基础URL本身就是API路径，也尝试检查
        if parsed_base.path.strip('/') in [p.strip('/') for p in API_PATHS]:
             initial_check = self._check_single_api(base_url)
             if initial_check:
                  api_results[parsed_base.path] = initial_check


        with ThreadPoolExecutor(max_workers=min(self.max_workers, len(API_PATHS) + 1)) as executor: # API检查线程数不超过路径数+1
            future_to_path = {}
            for path in API_PATHS:
                 api_url = urljoin(f"{scheme}://{domain}", path)
                 # 避免重复检查基础URL
                 if api_url != base_url or not initial_check:
                    future_to_path[executor.submit(self._check_single_api, api_url)] = path

            for future in future_to_path:
                path = future_to_path[future]
                try:
                    result = future.result()
                    if result:
                         api_results[path] = result
                except Exception as exc:
                     # print(f"{Fore.YELLOW}检查API端点 {path} 时发生错误: {exc}") # 调试用
                     pass

        return api_results

    def _check_single_api(self, url):
        """检查单个API端点URL是否存在。"""
        try:
            response = requests.head(
                url,
                headers=self.headers,
                timeout=self.timeout / 4, # 单个API检查超时更短
                verify=False,
                allow_redirects=False
            )
            # 200 OK, 201 Created, 204 No Content, 401 Unauthorized, 403 Forbidden 都可能指示API存在
            if response.status_code in [HTTP_OK, HTTP_CREATED, HTTP_NO_CONTENT, HTTP_UNAUTHORIZED, HTTP_FORBIDDEN]:
                 result = {'exists': True, 'status': response.status_code}
                 content_type = response.headers.get('Content-Type', '')
                 if 'application/json' in content_type.lower():
                     result['content_type_hint'] = 'JSON'
                 return result
        except requests.exceptions.RequestException:
             pass
        return None # 不存在或发生其他错误

    def analyze_headers_and_cookies(self, response):
        """分析HTTP响应头和Cookie，寻找服务器类型和框架的签名。"""
        headers = response.headers
        cookies = response.cookies
        analysis = {
            'headers': {},
            'cookies': {},
            'backend_frameworks': set(),
        }
        common_headers = ['Server', 'X-Powered-By', 'Content-Type', 'Cache-Control', 'X-AspNet-Version', 'X-AspNetMvc-Version', 'X-Request-Id', 'X-Runtime', 'Via', 'X-Generator', 'ETag', 'Last-Modified']
        for h in common_headers:
             if h in headers:
                 analysis['headers'][h] = headers[h]

        if 'Access-Control-Allow-Origin' in headers:
             analysis['headers']['cors_enabled'] = True
             analysis['headers']['cors_origin'] = headers['Access-Control-Allow-Origin']

        for cookie in cookies:
             # 只记录cookie名称，避免泄露敏感信息
             analysis['cookies'][cookie.name] = '存在' # 或 cookie.value 如果需要完整值

        # 检查 Set-Cookie 头部
        raw_set_cookie = response.raw.headers.getlist('Set-Cookie')

        for tech, signatures in self.backend_frameworks_signatures.items():
             for signature in signatures:
                 found = False
                 if signature.startswith('X-') or signature.startswith('Server') or signature.startswith('Via') or signature.startswith('X-Generator'):
                     header_name, _, header_value = signature.partition(': ')
                     header_key_found = next((k for k in headers if k.lower() == header_name.lower()), None)
                     if header_key_found:
                          if header_value:
                               if header_value.lower() in headers[header_key_found].lower():
                                     found = True
                          else: # 如果没有指定值，只检查header是否存在
                               found = True
                 elif signature.startswith('Set-Cookie: '):
                      cookie_sig = signature.split(': ', 1)[1]
                      if any(cookie_sig.lower() in h.lower() for h in raw_set_cookie):
                            found = True
                 elif signature in cookies: # 检查已解析的cookie名称
                      found = True

                 if found:
                      analysis['backend_frameworks'].add(tech)


        analysis['backend_frameworks'] = list(analysis['backend_frameworks'])
        return analysis

    def analyze_html_content(self, html_content, soup):
        """使用预编译的正则表达式分析HTML内容，寻找框架签名。"""
        analysis = {
             "vue_indicators": {},
             "spa_indicators": {},
             "other_frameworks": {},
             "vue_version": None,
             "has_server_side_hints": False,
             "general_frontend_libs": [] # 新增通用前端库列表
        }

        if not html_content:
            return analysis, False, False

        analysis["vue_indicators"] = find_matches(self.compiled_vue_patterns, html_content)
        is_vue = any(indicator["found"] for indicator in analysis["vue_indicators"].values())

        if is_vue and analysis["vue_indicators"].get("Vue库引用", {}).get("found") and soup:
             scripts = soup.find_all('script', src=True)
             # 更灵活的版本匹配模式
             version_pattern = re.compile(r'vue(?:-router|-resource)?(?:@|/)v?([0-9]+\.[0-9]+\.[0-9]+(?:[-.a-z0-9]+)?)', re.IGNORECASE)
             for script in scripts:
                  src = script['src']
                  version_match = version_pattern.search(src)
                  if version_match:
                      analysis["vue_version"] = version_match.group(1)
                      break # 找到版本号即可

        analysis["spa_indicators"] = find_matches(self.compiled_spa_patterns, html_content)
        is_spa = any(indicator["found"] for indicator in analysis["spa_indicators"].values())

        # 检查通用前端库
        general_libs_matches = find_matches({"通用前端库": self.compiled_spa_patterns.get("通用前端库", [])}, html_content)
        if general_libs_matches.get("通用前端库", {}).get("found"):
             analysis["general_frontend_libs"] = general_libs_matches["通用前端库"]["evidence"]


        primary_frontend = None
        framework_scores = {} # 用于更准确判断主要前端框架

        # 计分 Vue
        if is_vue:
            score = sum(len(v.get("evidence", [])) for k, v in analysis["vue_indicators"].items())
            framework_scores["Vue"] = score

        # 计分其他框架
        for framework, patterns in self.compiled_frontend_patterns.items():
             # 避免重复计分Vue
             if framework == "Vue":
                 continue
             framework_matches = find_matches({framework: patterns}, html_content)[framework]
             analysis["other_frameworks"][framework] = framework_matches
             if framework_matches.get("found"):
                  score = len(framework_matches.get("evidence", []))
                  framework_scores[framework] = score

        # 根据得分选择主要前端框架
        if framework_scores:
             primary_frontend = max(framework_scores, key=framework_scores.get)

        analysis["primary_frontend_framework"] = primary_frontend

        # 检查服务器端渲染/模板引擎痕迹
        server_side_patterns = [
             re.compile(r'<\?php'), re.compile(r'<%=.*?%>'), re.compile(r'<asp:'), # PHP, ASP, JSP
             re.compile(r'<jsp:'), re.compile(r'th:(text|each|if|unless)', re.IGNORECASE), # Thymeleaf
             re.compile(r'\{%\s*(load|include|extends|block)', re.IGNORECASE), # Django/Jinja2
             re.compile(r'__VIEWSTATE', re.IGNORECASE), # ASP.NET WebForms
             re.compile(r'<\?xml'), re.compile(r'<!DOCTYPE html') # 基本HTML结构
        ]
        html_head_sample = html_content[:2000] # 只检查头部以提高效率
        html_tail_sample = html_content[-2000:] if len(html_content) > 2000 else ""
        for pattern in server_side_patterns:
             if pattern.search(html_head_sample) or pattern.search(html_tail_sample):
                 analysis["has_server_side_hints"] = True
                 break

        return analysis, is_vue, is_spa

    def check_site(self, url):
        """对单个网站进行全面的技术栈检查。"""
        start_time = time.time()
        original_url = url
        result = {
            "url": original_url, "final_url": None, "domain": None,
            "status_code": None, "error": None, "response_time": 0,
            "redirected": False, "analysis": {
                "headers_cookies": {}, "html_content": {}, "api_endpoints": {},
                "vue_detected": False, "spa_detected": False, "architecture": "Unknown",
                "frontend_framework": None, "backend_framework": None, "vue_version": None,
                "general_frontend_libs": [], # 添加通用前端库到结果结构
            }
        }

        # 1. 获取页面内容
        response = self.fetch_url(original_url)

        # 处理请求错误
        if isinstance(response, dict) and 'error' in response:
            result["error"] = response['error']
            result["status_code"] = response.get('status_code')
            result["final_url"] = response.get('url', original_url)
            result["response_time"] = round(time.time() - start_time, 2)
            try: result["domain"] = urlparse(original_url).netloc
            except Exception: pass
            return result

        # 请求成功，记录基本信息
        result["status_code"] = response.status_code
        result["final_url"] = response.url
        try:
            result["domain"] = urlparse(response.url).netloc
        except Exception:
            result["domain"] = "未知"

        if response.url != self._normalize_url(original_url) and response.url != original_url: # 考虑规范化后的URL
             result["redirected"] = True

        try:
            # 2. 分析头部和Cookie
            header_cookie_analysis = self.analyze_headers_and_cookies(response)
            result["analysis"]["headers_cookies"] = header_cookie_analysis

            detected_backend_frameworks = set(header_cookie_analysis.get("backend_frameworks", []))

            # 如果检测到多个后端框架，优先选择更具体的
            if len(detected_backend_frameworks) > 1:
                # 简单排序，将长度更长的（更具体的签名）放在前面
                sorted_backends = sorted(list(detected_backend_frameworks), key=len, reverse=True)
                result["analysis"]["backend_framework"] = sorted_backends[0]
            elif detected_backend_frameworks:
                 result["analysis"]["backend_framework"] = list(detected_backend_frameworks)[0]
            else:
                 # 如果没有明确检测到框架，检查服务器和X-Powered-By头部作为提示
                 server_hint = header_cookie_analysis.get('headers', {}).get('Server')
                 powered_by_hint = header_cookie_analysis.get('headers', {}).get('X-Powered-By')
                 hints = [h for h in [server_hint, powered_by_hint] if h and 'cloudflare' not in h.lower()] # 过滤掉常见的CDN/代理提示
                 if hints:
                     result["analysis"]["backend_framework"] = f"提示: {' / '.join(hints)}"
                 else:
                     result["analysis"]["backend_framework"] = "未检测到"


            html_content = ""
            content_type = response.headers.get('Content-Type', '').lower()
            soup = None

            # 3. 如果是HTML内容，进行HTML分析
            if 'html' in content_type:
                # 尝试不同的编码
                encodings = ['utf-8', 'gbk', 'latin-1']
                for enc in encodings:
                    try:
                        html_content = response.content.decode(enc)
                        break
                    except UnicodeDecodeError:
                        html_content = "" # 解码失败，尝试下一个
                if not html_content and response.text: # 如果尝试解码失败，使用requests的text（可能不准确）
                     html_content = response.text

                if html_content:
                     try:
                         soup = BeautifulSoup(html_content, 'html.parser')
                     except Exception as e:
                         result["error"] = f"HTML解析错误: {str(e)}"
                         pass

            if soup:
                 html_analysis, is_vue, is_spa = self.analyze_html_content(html_content, soup)
                 result["analysis"]["html_content"] = html_analysis
                 result["analysis"]["vue_detected"] = is_vue
                 result["analysis"]["spa_detected"] = is_spa
                 result["analysis"]["frontend_framework"] = html_analysis.get("primary_frontend_framework")
                 result["analysis"]["vue_version"] = html_analysis.get("vue_version")
                 result["analysis"]["general_frontend_libs"] = html_analysis.get("general_frontend_libs", [])

            else:
                 result["analysis"]["frontend_framework"] = f"非HTML内容 ({content_type})"
                 # 对于非HTML内容，也尝试检查API
                 should_check_apis = True


            # 4. 检查常见的API端点
            # 检查API的条件：检测到SPA/Vue, HTML中检测到API调用模式，或者是非HTML内容
            should_check_apis = result["analysis"]["spa_detected"] or result["analysis"]["vue_detected"] or \
                                (soup and result["analysis"]["html_content"].get("spa_indicators", {}).get("API调用模式", {}).get("found")) or \
                                (not soup and result["status_code"] == HTTP_OK) # 如果不是HTML，且状态码正常，也尝试检查API

            if should_check_apis and result["domain"]:
                 result["analysis"]["api_endpoints"] = self.check_api_endpoints(result["final_url"])
            else:
                 result["analysis"]["api_endpoints"] = {"info": "不符合API检查条件或域名无效"}


            # 5. 推断架构类型
            arch = "未知"
            has_frontend_framework = result["analysis"]["frontend_framework"] is not None and result["analysis"]["frontend_framework"] != "未检测到" and "非HTML内容" not in str(result["analysis"]["frontend_framework"])
            has_backend_framework = result["analysis"]["backend_framework"] is not None and result["analysis"]["backend_framework"] != "未检测到" and "提示:" not in str(result["analysis"]["backend_framework"])
            backend_hints_only = result["analysis"]["backend_framework"] is not None and "提示:" in str(result["analysis"]["backend_framework"])
            found_apis = any(info.get('exists') for info in result["analysis"]["api_endpoints"].values())
            found_api_calls_in_html = soup and result["analysis"]["html_content"].get("spa_indicators", {}).get("API调用模式", {}).get("found")
            has_ssr_hints = soup and result["analysis"]["html_content"].get("has_server_side_hints", False)
            is_plain_html = soup and not has_frontend_framework and not has_ssr_hints and not found_apis and not has_backend_framework and not backend_hints_only

            if result["status_code"] >= 400: # 客户端或服务器错误
                 arch = f"无法访问或错误 ({result['status_code']})"
            elif result["status_code"] >= 300 and result["status_code"] < 400: # 重定向
                 arch = f"重定向 ({result['status_code']})"
            elif 'html' not in content_type:
                 arch = f"非HTML内容 ({content_type})"
            elif has_frontend_framework and (found_apis or found_api_calls_in_html or has_backend_framework or backend_hints_only):
                 # 如果有明确前端框架，且有后端/API迹象
                 arch = "前后端分离架构 (SPA/MPA + API)"
            elif has_frontend_framework:
                 # 只有前端框架，没有明显后端/API迹象
                 arch = "现代前端应用 (SPA/MPA)"
            elif has_backend_framework or backend_hints_only:
                 # 有后端框架或提示，没有前端框架
                 if has_ssr_hints:
                      arch = "服务器端渲染 (传统架构)"
                 elif found_apis:
                      arch = "后端服务/API (可能无复杂前端)"
                 else:
                      arch = "后端技术存在 (架构不明确)"
            elif has_ssr_hints:
                 # 有SSR痕迹，没有明确前端/后端框架
                 arch = "传统服务器端渲染页面"
            elif is_plain_html:
                 # 看起来像是简单的HTML页面
                 body_tag = soup.find('body')
                 if body_tag and len(body_tag.find_all(recursive=False)) < 10 and len(soup.find_all('script')) < 5 and not soup.find_all('link', rel='stylesheet'):
                      arch = "静态网站 (非常简单)"
                 else:
                      arch = "静态或传统网站" # 可能是静态生成或简单传统页面
            else:
                 arch = "传统网站 (架构不明确)" # 难以归类

            result["analysis"]["architecture"] = arch

        except Exception as e:
             result["error"] = f"分析过程中出错: {str(e)}"
             result["analysis"]["architecture"] = f"分析失败 ({str(e)[:30]}...)" # 更新架构状态为失败

        result["response_time"] = round(time.time() - start_time, 2)
        return result

    def format_result_for_row(self, result):
        """将单个检测结果格式化为pandas DataFrame的一行数据。"""
        analysis = result.get("analysis", {})
        frontend_fw = analysis.get('frontend_framework')
        backend_fw = analysis.get('backend_framework')
        general_libs = analysis.get('general_frontend_libs', [])

        frontend_display = "未检测到"
        if frontend_fw and "非HTML内容" not in str(frontend_fw):
            version_str = f" (v{analysis['vue_version']})" if analysis.get('vue_version') else ""
            # 组合主要框架和检测到的通用库
            libs_str = f" + {'/'.join(general_libs[:3])}" if general_libs else "" # 只显示前3个通用库
            frontend_display = f"{frontend_fw}{version_str}{libs_str}"
        elif frontend_fw:
             frontend_display = frontend_fw
        elif general_libs: # 如果没有主要框架，但检测到通用库
             frontend_display = f"通用库: {'/'.join(general_libs[:3])}"


        backend_display = "未检测到"
        if backend_fw:
             backend_display = backend_fw

        api_info = analysis.get('api_endpoints', {})
        api_display = "未检查"
        # 检查API的条件与 check_site 中的逻辑保持一致
        should_check_apis = analysis.get("spa_detected") or analysis.get("vue_detected") or \
                            analysis.get("html_content", {}).get("spa_indicators", {}).get("API调用模式", {}).get("found") or \
                            ("非HTML内容" in str(frontend_fw) or str(frontend_fw) == "未检测到" and result.get("status_code") == HTTP_OK)


        if should_check_apis:
             if api_info.get('error'):
                  api_display = f"检查API出错: {api_info['error'][:20]}..."
             else:
                  found_endpoints = [path for path, info in api_info.items() if info.get('exists')]
                  if found_endpoints:
                       api_display = f"存在: {', '.join(found_endpoints[:3])}" # 只显示前3个API端点
                       if len(found_endpoints) > 3:
                            api_display += "..."
                  else:
                       api_display = "未检测到常见API路径"
        elif not should_check_apis and api_info.get("info"): # 如果不符合检查条件，显示未检查信息
             api_display = api_info.get("info")


        error_display = result.get('error', '')
        if error_display:
            error_display = error_display[:80] + '...' if len(error_display) > 80 else error_display


        return [
            result.get('url', 'N/A'),
            result.get('final_url', 'N/A') if result.get('redirected') else '无重定向',
            result.get('status_code', 'N/A'),
            f"{result.get('response_time', 0):.2f}秒",
            analysis.get('architecture', '未知'),
            frontend_display,
            backend_display,
            api_display,
            error_display
        ]

    def save_results_to_excel(self, results, filename='ok.xlsx'):
        """
        将检测结果保存到Excel文件。
        """
        if not results:
            print(f"{Fore.YELLOW}没有检测结果可供保存到Excel。")
            return

        headers = [
            "原始 URL", "最终 URL", "状态码", "耗时",
            "推测架构", "前端框架/库", "后端框架/技术", "API端点检查", "错误信息"
        ]

        table_data = [self.format_result_for_row(result) for result in results]

        try:
            df = pd.DataFrame(table_data, columns=headers)
            df.to_excel(filename, index=False)
            print(f"\n{Fore.GREEN}检测结果已成功保存到 '{filename}'")
        except ImportError:
            print(f"\n{Fore.RED}错误: 无法保存到Excel。请安装pandas和openpyxl库: pip install pandas openpyxl")
        except Exception as e:
            print(f"\n{Fore.RED}保存Excel文件时出错 '{filename}': {e}")


def process_url_list(file_path, detector):
    """从文件读取URL列表，并使用ThreadPoolExecutor并发处理。"""
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            urls = [line.strip() for line in file if line.strip() and not line.strip().startswith('#')]
    except FileNotFoundError:
        print(f"{Fore.RED}错误: 文件未找到 '{file_path}'")
        sys.exit(1)
    except Exception as e:
        print(f"{Fore.RED}读取文件时出错 '{file_path}': {e}")
        sys.exit(1)

    if not urls:
        print(f"{Fore.YELLOW}文件中未找到有效的URL。")
        return []

    print(f"{Fore.CYAN}准备检测 {len(urls)} 个URL (使用 {detector.max_workers} 个工作线程)...")

    all_results = []
    processed_count = 0
    total_urls = len(urls)

    # 显示处理进度
    def update_progress(current, total, url):
        print(f"{Fore.YELLOW}正在处理 ({current}/{total}): {url[:80]}{'...' if len(url) > 80 else ' '}", end='\r')
        sys.stdout.flush()


    with ThreadPoolExecutor(max_workers=detector.max_workers) as executor:
        future_to_url = {executor.submit(detector.check_site, url): url for url in urls}

        for future in future_to_url:
            url = future_to_url[future]
            try:
                result = future.result()
                all_results.append(result)
            except Exception as exc:
                # print(f"\n{Fore.RED}{'='*60}") # 调试用
                # print(f"{Fore.RED}处理 {url} 时发生意外错误: {exc}") # 调试用
                # print(f"{Fore.RED}{'='*60}") # 调试用
                all_results.append({
                     "url": url,
                     "final_url": url,
                     "domain": urlparse(url).netloc if urlparse(url).netloc else "N/A",
                     "status_code": "错误",
                     "error": f"处理过程中发生意外错误: {exc}",
                     "response_time": 0,
                     "redirected": False,
                     "analysis": {"architecture": "处理失败"} # 添加一个简略的分析信息
                })
            finally:
                 processed_count += 1
                 update_progress(processed_count, total_urls, url)


    print("\n" + "="*100)
    # detector.print_results_table(all_results) # 移除打印表格，改用保存Excel

    # --- 打印汇总报告 ---
    print(f"\n{Fore.CYAN}{'='*60}")
    print(f"{Fore.CYAN}===== 检测结果汇总 =====")
    print(f"{Fore.CYAN}{'-'*60}")

    total_checked = len(all_results)
    successful_sites = sum(1 for r in all_results if not r.get('error'))
    error_sites = total_checked - successful_sites

    print(f"{Fore.BLUE}总计URL: {total_checked}")
    print(f"{Fore.RED}检测出错的网站: {error_sites}")
    print(f"{Fore.GREEN}成功检测的网站: {successful_sites}")

    # 汇总前端框架
    frontend_counts = {}
    for r in all_results:
         if not r.get('error') and r.get('analysis', {}).get('frontend_framework'):
              fw = r.get('analysis', {}).get('frontend_framework')
              if fw and "非HTML内容" not in str(fw) and "未检测到" not in str(fw):
                   # 统计主要框架
                   main_fw = fw.split(' ')[0] # 取第一个词作为主要框架
                   frontend_counts[main_fw] = frontend_counts.get(main_fw, 0) + 1
              elif r.get('analysis', {}).get('general_frontend_libs'):
                   # 如果没有主要框架，但有通用库，可以简单统计通用库
                   for lib in r.get('analysis', {}).get('general_frontend_libs', []):
                        frontend_counts[lib] = frontend_counts.get(lib, 0) + 1


    if frontend_counts:
        print(f"\n{Fore.MAGENTA}前端框架/库分布:")
        sorted_frontend = sorted(frontend_counts.items(), key=lambda item: item[1], reverse=True)
        for fw, count in sorted_frontend:
            percentage = (count / successful_sites * 100) if successful_sites > 0 else 0
            print(f"  {Fore.WHITE}- {fw}: {count} ({percentage:.1f}%)")

    # 汇总后端框架
    backend_counts = {}
    for r in all_results:
         if not r.get('error') and r.get('analysis', {}).get('backend_framework'):
              fw = r.get('analysis', {}).get('backend_framework')
              if fw and "提示:" not in str(fw) and "未检测到" not in str(fw):
                   backend_counts[fw] = backend_counts.get(fw, 0) + 1


    if backend_counts:
        print(f"\n{Fore.MAGENTA}后端框架/技术分布:")
        sorted_backend = sorted(backend_counts.items(), key=lambda item: item[1], reverse=True)
        for fw, count in sorted_backend:
            percentage = (count / successful_sites * 100) if successful_sites > 0 else 0
            print(f"  {Fore.WHITE}- {fw}: {count} ({percentage:.1f}%)")

    # 汇总架构类型
    arch_counts = {}
    for r in all_results:
         if not r.get('error'):
              arch = r.get('analysis', {}).get('architecture', '未知')
              arch_counts[arch] = arch_counts.get(arch, 0) + 1
         else: # 统计出错的网站
              arch_counts["处理失败"] = arch_counts.get("处理失败", 0) + 1


    if arch_counts:
        print(f"\n{Fore.MAGENTA}架构类型分布:")
        sorted_arch = sorted(arch_counts.items(), key=lambda item: item[1], reverse=True)
        for arch, count in sorted_arch:
            percentage = (count / total_checked * 100) if total_checked > 0 else 0 # 架构分布基于总检查数
            print(f"  {Fore.WHITE}- {arch}: {count} ({percentage:.1f}%)")

    print(f"{Fore.CYAN}{'-'*60}")

    return all_results


def main():
    """主函数，解析命令行参数并启动检测，最后保存结果到Excel。"""
    parser = argparse.ArgumentParser(
        description='Web应用架构与技术栈检测脚本 (结果保存到 ok.xlsx)',
        formatter_class=argparse.RawTextHelpFormatter
    )
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument('-u', '--url', help='需要检测的单个网站URL')
    input_group.add_argument('-L', '--list', dest='url_list_file',
                             help='包含多个URL的文件路径 (每行一个URL, #开头为注释)')
    parser.add_argument('-t', '--timeout', type=int, default=DEFAULT_TIMEOUT,
                        help=f'HTTP请求超时时间(秒) (默认: {DEFAULT_TIMEOUT})')
    parser.add_argument('-w', '--workers', type=int, default=DEFAULT_MAX_WORKERS,
                        help=f'处理URL列表时的并行工作线程数 (默认: {DEFAULT_MAX_WORKERS})')
    args = parser.parse_args()

    if args.workers < 1:
        print(f"{Fore.RED}错误: 工作线程数必须至少为 1")
        sys.exit(1)

    detector = WebAppDetector(timeout=args.timeout, max_workers=args.workers)

    all_results = []

    if args.url:
        print(f"{Fore.CYAN}正在检测单个URL: {args.url}")
        result = detector.check_site(args.url)
        all_results.append(result)
    elif args.url_list_file:
        all_results = process_url_list(args.url_list_file, detector)

    # 将所有结果保存到Excel文件
    if all_results:
         detector.save_results_to_excel(all_results, 'ok.xlsx')
    else:
         print(f"{Fore.YELLOW}没有结果可保存到Excel文件。")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}操作被用户中断")
        sys.exit(1)
    except Exception as e:
        print(f"\n{Fore.RED}发生未预料的顶层错误: {e}")
        sys.exit(1)
