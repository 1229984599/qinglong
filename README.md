# QingLong 青龙面板脚本集合
[![Python Version](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org)
[![License](https://img.shields.io/badge/License-CC%20BY--NC--SA%204.0-lightgrey.svg)](https://creativecommons.org/licenses/by-nc-sa/4.0/deed.zh)

## 项目简介

这是一个基于青龙面板的自动化脚本集合项目，主要用于实现各种网站的自动签到、数据采集等自动化任务。项目采用Python编写，支持多个平台的自动化操作。

## 功能特性

- ✨ GLaDOS自动签到 - 每日自动签到GLaDOS，延长账号有效期
- 📷 水墨图床自动签到 - 水墨图床每日签到
- 🌐 IKuuu机场签到 - IKuuu机场自动签到获取流量
- 📱 益丰API签到 - 支持多账号的益丰API面板签到
- 📝 ztjun博客签到 - 支持多账号的ztjun博客自动签到
- 🎨 文心一格签到 - 百度文心一格AI绘画平台自动签到
- 🌟 更多功能持续开发中...

## 环境要求

- Python 3.10+
- 青龙面板环境

## 依赖安装

```bash
# 使用PDM安装依赖（推荐）
pdm install
```

## 主要依赖

- requests~=2.31.0
- beautifulsoup4~=4.12.3
- loguru>=0.7.3
- httpx>=0.28.1

## 使用说明

### 1. GLaDOS自动签到

在青龙面板环境变量中添加：
- 变量名：`glados_cookie`
- 值：您的GLaDOS账号Cookie

定时任务配置：
```bash
0 9 * * * python3 glados.py
```

### 2. 水墨图床自动签到

在青龙面板环境变量中添加：
- 变量名：`img_ink_cookie`
- 值：您的水墨图床Cookie

定时任务配置：
```bash
0 9 * * * python3 img_ink.py
```

### 3. IKuuu机场签到

在青龙面板环境变量中添加：
- 变量名：`ikuuu_cookie`
- 值：账号#密码 格式，例如：`user@example.com#password`

定时任务配置：
```bash
0 6 * * * python3 ikun.py
```

### 4. 益丰API签到

在青龙面板环境变量中添加：
- 变量名：`ephone`
- 值：支持多账号，格式：`account#password account2#password2`

定时任务配置：
```bash
0 7 * * * python3 ephone.py
```

### 5. ztjun博客签到

在青龙面板环境变量中添加：
- 变量名：`ztjun_cookie`
- 值：支持多账号，格式：`account#password@account2#password2`

定时任务配置：
```bash
0 6 * * * python3 ztjun.py
```

### 6. 文心一格签到

在青龙面板环境变量中添加：
- 变量名：`yige_cookie`
- 值：您的文心一格Cookie

定时任务配置：
```bash
0 6 * * * python3 yige.py
```

## 配置说明

所有脚本均支持在青龙面板中配置定时任务，建议参考各脚本头部的cron表达式进行配置。

## 注意事项

1. 请确保填写的Cookie等信息正确有效
2. 建议定时任务不要设置过于频繁，以免对目标网站造成压力
3. 使用脚本时请遵守目标网站的使用规则和条款

## 更新日志

- 2024-03-04: 新增水墨图床自动签到功能
- 2023-10-03: 新增GLaDOS自动签到功能

## 贡献指南

欢迎提交Issue和Pull Request，一起完善这个项目！

## 开源协议

本项目采用 CC BY-NC-SA 4.0 协议开源。这意味着您可以自由地分享、修改本项目的代码，但必须：
1. 保留原作者（@moxiaoying）的版权信息
2. 不得用于商业目的
3. 以相同的协议共享您的修改

详见 [CC BY-NC-SA 4.0](https://creativecommons.org/licenses/by-nc-sa/4.0/deed.zh) 协议全文。

## 联系方式

- 作者：moxiaoying
- 邮箱：768091671@qq.com
- GitHub：[@1229984599](https://github.com/1229984599)

> **版权声明**
> 
> Copyright © 2024 moxiaoying. All rights reserved.
> 
> 本项目基于 CC BY-NC-SA 4.0 协议开源。这意味着您：
> - ✅ 必须给出适当的署名，提供指向本许可证的链接，同时标明是否作出修改
> - ✅ 可以复制、分发、展示和表演本作品
> - ✅ 可以二次创作，但必须基于与原先许可协议相同的许可协议分发您的贡献
> - ❌ 不得将本作品用于商业目的
> 
> 使用本项目代码时，请保留作者（@moxiaoying）的版权信息。
> 
> 完整许可协议：[CC BY-NC-SA 4.0](https://creativecommons.org/licenses/by-nc-sa/4.0/deed.zh)

