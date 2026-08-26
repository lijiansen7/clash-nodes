@echo off
chcp 936 >nul
setlocal enabledelayedexpansion
cd /d "%~dp0"
set "PYTHONUTF8=1"

where py >nul 2>nul
if errorlevel 1 (
    echo [错误] 未找到 Python, 请先安装 Python 3.8+ 并勾选 "Add to PATH"
    pause
    exit /b 1
)

:menu
cls
echo.
echo  ============================================================
echo     Clash 免费节点测试工具箱 (mihomo 内核)
echo  ============================================================
echo.
echo    [1] 完整流程  发现订阅 + 下载 + mihomo实测 + 导出分流配置
echo    [2] 快速测试  用上次导出的节点重新测速 (约1-2分钟)
echo    [3] 重跑全量  走缓存不重新下载, 重新测速 (约5分钟)
echo    [4] 更新内核  下载/更新 mihomo.exe
echo    [5] 单个订阅  输入订阅链接直接测试
echo    [6] 清理临时  删除临时文件和缓存
echo    [0] 退出
echo.
set /p choice=  请选择: 

if "%choice%"=="1" goto full
if "%choice%"=="2" goto quick
if "%choice%"=="3" goto rerun
if "%choice%"=="4" goto kernel
if "%choice%"=="5" goto urltest
if "%choice%"=="6" goto clean
if "%choice%"=="0" exit /b
goto menu

:full
cls
echo [步骤1/2] 检查 mihomo 内核 ...
if not exist mihomo.exe (
    echo   未找到 mihomo.exe, 正在自动下载 ...
    py get_mihomo.py
    if errorlevel 1 (
        echo [错误] 内核下载失败, 请检查网络后重试
        pause
        goto menu
    )
) else (
    echo   内核已存在: mihomo.exe
)
echo.
echo [步骤2/2] 开始完整测试 (剔除弱订阅 + 剔除CN节点, 2秒超时) ...
echo.
py clash_node_tester.py --discover --engine mihomo --export-proxy-ok mihomo_alive.yaml --min-alive 3
goto result

:quick
cls
echo 快速测试: 用 alive_nodes.yaml 重新测速 ...
py mihomo_engine.py --quick
goto result

:rerun
cls
echo 重跑全量测试 (走缓存, 2秒超时, 剔除弱订阅+CN节点) ...
py mihomo_engine.py --full --min-alive 3
goto result

:kernel
cls
echo 正在下载/更新 mihomo 内核 ...
py get_mihomo.py
goto result

:urltest
cls
set /p suburl=  请输入订阅链接: 
if "%suburl%"=="" goto menu
echo.
echo 正在测试: %suburl%
py clash_node_tester.py --url "%suburl%" --engine mihomo --export-proxy-ok mihomo_alive.yaml
goto result

:clean
cls
echo 清理临时文件 ...
del /q _mihomo_latest.zip _mock_cert.pem _mock_key.pem _t.yaml debug_out.txt 2>nul
if exist _mihomo rd /s /q _mihomo
echo 已清理 (保留节点缓存 _nodes_cache.pkl, 如需彻底删除请手动删除该文件)
pause
goto menu

:result
echo.
echo  ============================================================
echo   完成! 结果文件:
echo     mihomo_alive.yaml   完整分流配置 (直接导入 Clash/Mihomo)
echo     mihomo_alive_quick.yaml  快速测试结果 (如有)
echo  ============================================================
echo.
pause
goto menu