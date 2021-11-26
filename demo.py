# -*- coding: utf-8 -*-
"""在 10 秒之后加载另一个 URL"""

import threading
import time
import webview


def change_url():
    # 等待 10 秒再执行:
    time.sleep(10)

    # 加载 URL:
    webview.load_url("https://pywebview.github.io/hello/")


if __name__ == "__main__":
    t = threading.Thread(target=change_url)
    t.start()

    webview.create_window("加载 URL 示例", "http://www.baidu.com")