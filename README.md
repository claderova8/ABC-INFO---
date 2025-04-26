Web 应用技术栈检测工具
一个用于检测网站所使用的前端、后端技术框架及常见 API 端点的 Python 脚本。支持检测单个 URL 或从文件批量读取 URL 进行检测，并将结果保存到 Excel 文件。

功能特性
灵活输入: 支持通过命令行参数指定单个 URL 或一个包含多个 URL 的文件。
技术栈检测:
分析 HTTP 响应头部和 Cookie，识别常见的后端框架和服务器。
解析 HTML 内容和 JavaScript 代码，检测前端框架 (Vue, React, Angular, jQuery, Svelte, Ember.js 等) 和通用前端库。
尝试识别 Vue.js 的版本信息。
API 端点探测: 对一些常见的 API 路径进行 HEAD 请求检查，判断其存在性。
架构推断: 根据检测到的技术栈信息，尝试推断网站的架构类型（如 前后端分离、传统服务端渲染、静态网站等）。
并发处理: 使用线程池并发处理 URL 列表，提高效率。
Excel 输出: 将详细的检测结果整洁地保存到 ok.xlsx 文件中，便于查阅和进一步分析。
控制台报告: 在控制台输出检测进度和汇总统计报告。
可配置: 允许用户通过命令行参数设置请求超时时间 (-t) 和并发线程数 (-w)。
错误处理: 捕获请求和分析过程中可能出现的错误。
依赖项
要运行此脚本，你需要安装 Python 3 以及以下第三方库：

requests
beautifulsoup4 (bs4)
colorama
pandas
openpyxl
使用 pip 安装所有依赖项的命令如下：

Bash

pip install requests beautifulsoup4 colorama pandas openpyxl
如果你的系统中同时存在 Python 2 和 Python 3，请确保使用 pip3 来为 Python 3 安装库：

Bash

pip3 install requests beautifulsoup4 colorama pandas openpyxl
安装
将脚本代码复制并保存为一个 Python 文件，例如 web_detector.py。
（可选）创建一个虚拟环境并激活它：
Bash

python -m venv .venv
# Windows
.venv\Scripts\activate
# macOS/Linux
source .venv/bin/activate
在虚拟环境中安装依赖项：
Bash

pip install requests beautifulsoup4 colorama pandas openpyxl
使用方法
在终端中导航到脚本所在的目录，然后运行脚本。脚本需要至少一个参数来指定要检测的 URL 或 URL 列表文件。

查看帮助信息：

Bash

python web_detector.py -h
输出将如下所示：

usage: web_detector.py [-h] (-u URL | -L URL_LIST_FILE) [-t TIMEOUT] [-w WORKERS]

Web应用架构与技术栈检测脚本 (结果保存到 ok.xlsx)

options:
  -h, --help            show this help message and exit
  -u URL, --url URL     需要检测的单个网站URL
  -L URL_LIST_FILE, --list URL_LIST_FILE
                        包含多个URL的文件路径 (每行一个URL, #开头为注释)
  -t TIMEOUT, --timeout TIMEOUT
                        HTTP请求超时时间(秒) (默认: 15)
  -w WORKERS, --workers WORKERS
                        处理URL列表时的并行工作线程数 (默认: 10)
检测单个 URL
使用 -u 或 --url 参数后跟要检测的 URL。

Bash

python web_detector.py -u https://github.com
检测 URL 列表文件
创建一个纯文本文件（例如 urls.txt），每行放置一个完整的 URL。以 # 开头的行会被视为注释并忽略。

示例 urls.txt 文件：

# 我的目标网站列表

https://www.python.org
https://www.npmjs.com
http://example.com # 一个示例网站
然后使用 -L 或 --list 参数指定文件路径。

Bash

python web_detector.py -L urls.txt
可选参数
-t TIMEOUT, --timeout TIMEOUT: 设置单个 HTTP 请求的最大等待时间（秒）。默认是 15 秒。
Bash

python web_detector.py -u https://slow-loading-site.com -t 30
-w WORKERS, --workers WORKERS: 设置处理 URL 列表时同时进行的请求数量。默认是 10。仅在使用 -L 参数时有效。
Bash

python web_detector.py -L large_url_list.txt -w 25
输出文件
脚本成功运行后，会在与脚本相同的目录下生成一个名为 ok.xlsx 的 Excel 文件。此文件包含一个表格，每一行对应一个被检测的 URL，列出了详细的检测结果和分析。

表格列说明：

原始 URL: 用户输入的或列表中读取的原始 URL。
最终 URL: 实际访问的 URL，如果发生重定向则不同于原始 URL。
状态码: HTTP 响应状态码（例如 200, 404, 301）。
耗时: 完成该 URL 检测的总时间（秒）。
推测架构: 脚本根据检测结果推断的网站架构类型。
前端框架/库: 检测到的主要前端框架或重要的通用前端库。
后端框架/技术: 检测到的后端框架、服务器或其他技术提示。
API 端点检查: 常见 API 路径的检查结果（是否存在，状态码）。
错误信息: 如果检测过程中遇到错误，会在此处显示简要说明。
同时，控制台会打印一个方便查看的汇总报告，总结检测总数、成功/失败数以及各技术栈和架构类型的分布比例。

注意事项
本工具通过分析公开可获取的信息（HTTP 头部、HTML、可访问的 JS/CSS 文件中的特征串、常见路径探测等）来推断技术栈。并非所有网站都以标准方式暴露这些信息，因此检测结果可能存在一定的局限性或不准确性。
API 探测仅检查少数预定义的常见路径，无法发现所有 API 接口。
请遵守道德和法律规范，仅在您拥有合法授权的情况下使用本工具进行检测。对未知或未授权的系统进行扫描可能被视为非法行为。
