# Web 应用技术栈检测工具

一个用于检测网站所使用的前端、后端技术框架及常见 API 端点的 Python 脚本。支持检测单个 URL 或从文件批量读取 URL 进行检测，并将结果保存到 Excel 文件。

## 功能特性

* **灵活输入**: 支持通过命令行参数指定单个 URL (`-u`) 或一个包含多个 URL 的文件 (`-L`)。
* **技术栈检测**:
    * 分析 HTTP 响应头部 (`Server`, `X-Powered-By` 等) 和 Cookie，识别常见的后端框架和服务器。
    * 解析 HTML 内容和 JavaScript 代码（包括外部脚本和内联代码），检测前端框架 (Vue, React, Angular, jQuery, Svelte, Ember.js 等) 和通用前端库。
    * 尝试识别 Vue.js 的版本信息。
* **API 端点探测**: 对一些预定义的常见 API 路径（如 `/api`, `/v1`, `/graphql`, `/wp-json` 等）进行 HEAD 请求检查，判断其存在性及状态码。
* **架构推断**: 根据检测到的前端、后端和 API 迹象，尝试推断网站的架构类型（如 前后端分离、传统服务端渲染、静态网站等）。
* **并发处理**: 使用线程池 (`concurrent.futures`) 并发处理 URL 列表，显著提高批量检测效率。
* **Excel 输出**: 将详细的检测结果整洁地保存到 `ok.xlsx` 文件中，每行代表一个 URL 的检测结果，便于查阅和进一步分析。
* **控制台报告**: 在控制台实时显示处理进度，并在检测完成后输出汇总统计报告，概览检测总数、成功/失败数以及各技术栈和架构类型的分布比例。
* **可配置**: 允许用户通过命令行参数自定义请求超时时间 (`-t TIMEOUT`) 和并发工作线程数 (`-w WORKERS`)。
* **错误处理**: 捕获 HTTP 请求错误、连接错误、超时以及分析过程中的异常，并在结果中标记错误信息。
* **URL 规范化**: 自动尝试添加 `https://` 或 `http://` 方案。
* **SSL 警告忽略**: 忽略不安全的 HTTPS 连接警告 (请注意其安全含义)。

## 依赖项

要运行此脚本，请确保你的系统安装了 **Python 3**。此外，你需要安装以下第三方 Python 库：

* `requests`: 用于处理 HTTP 请求。
* `beautifulsoup4`: 用于高效解析 HTML 和 XML。
* `colorama`: 用于在命令行输出中添加颜色，提升可读性。
* `pandas`: 核心数据处理库，用于构建和操作结果表格。
* `openpyxl`: pandas 写入 `.xlsx` 格式 Excel 文件的后端引擎。

**安装步骤：**

1.  使用 pip 安装所有依赖项。在你的终端或命令行中执行以下命令：

    ```bash
    pip install requests beautifulsoup4 colorama pandas openpyxl
    ```

2.  如果你的系统配置了多个 Python 版本，并且 `pip` 默认指向的是 Python 2 或其他版本，请尝试使用 `pip3` 来为 Python 3 安装库：

    ```bash
    pip3 install requests beautifulsoup4 colorama pandas openpyxl
    ```

3.  为了保持项目的依赖清晰和环境隔离，强烈建议在一个 [Python 虚拟环境](https://docs.python.org/3/library/venv.html) 中安装这些库。

## 安装

1.  将此代码保存为一个 Python 文件，例如 `web_detector.py`。
2.  打开你的终端或命令行界面，导航到你保存 `web_detector.py` 文件的目录。
3.  按照上述“依赖项”部分的说明，确保所有必需的库都已安装。

无需其他特殊的安装步骤，脚本本身就是一个可执行文件。

## 使用方法

脚本通过命令行参数来接收输入和配置行为。

首先，你可以运行以下命令来查看脚本的命令行参数帮助信息：

```bash
python web_detector.py -h
```

##
![image](https://github.com/user-attachments/assets/717c40e3-e339-434a-a772-7fdf8c283e47)

