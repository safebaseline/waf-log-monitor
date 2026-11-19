@echo off
chcp 65001 >nul
cd /d %~dp0
title WAF 攻击日志监控
echo 正在启动 WAF 攻击日志监控...
start "" http://127.0.0.1:8686
node server.js
pause
