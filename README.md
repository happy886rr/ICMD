# ICMD
ICMD注入版, 是一个cmd控制台注入版DLL插件, 通过ICMD.exe将ICMD.DLL注入到cme.exe中, 以便CMD控制台窗口可以调用系统dll中的API函数, 或是调用本地目录中的自制dll函数. 这次提供了32位与64位的 版本,使用一个工程文件选择win32或是 x64编译得到不用位数的程序版本.  改进: 解决了64位API传参的寄存器选择问题, 解决了stdcall, cdecl自适应调用的问题, 用户无需分辨函数是何种调用类型, 以及无需知道API函数 位于哪个dll中.  一次iload 多个dll, 调用API函数 时 ,无需再写dll名字, 非常接近原生C风格的书写语法.\

COPYRIGHT@2021~2099 REWRITE BY SLIMAY, VERSION 1.0
ICMD64 注入版[使用手册]


用法：
首先在批处理中, 仅需调用一次如下命令: ICMD [要注入的 DLL文件名]
ICMD ICMD64.DLL

也可以在批处理脚本开头, 加入icmd的调用头
32位调用头为：
@if ["%1"]==[""] (if exist "%windir%\syswow64\cmd.exe" (start %windir%\syswow64\cmd.exe /c "%~f0" 1&exit))
@icmd32

64位调用头为：
@icmd64


然后基本语法同CMD.EXE，主要区别在于SET增加了 *开关
原生API调用开关 SET *

SET *[返回值]=[函数名] [参数] [参数] ...


示例：
REM 普通文本字串前加T作为标识，宽字符字串前加L。如 L"1.ico"标识宽字符的 "1.ico"，其他类型无需任何标
    识, 也可以加 I整型, D高精度浮点, '字符'字符型, L'字符'宽字符型。宽字符串类型L, ANSI字符串类型A

REM 一次载入 所有DLL
set *= ILOAD L"USER32" L"KERNEL32" L"GDI32" L"GDIPLUS" L"MSVCRT"

set *hIcon = LoadImageW 0 L"1.ico" 1 0 0 16
set *hCMD  = GetConsoleWindow
set *hDC   = GetDC %hCMD%
set *      = DrawIconEx %hDC% %x% 0 %hIcon% 128 128 0 0 3

REM 如果要获取小数结果，请在变量名前加 ~ 符号， 表示返回小数结果
set ~ ret = sqrt 3.0
echo %ret%


内建函数：(备注: 5个内建函数 均为宽字符版本, 字符串参数均需要加 L 前缀 )
REM 载入DLL的命令, 如载入 DLL1, DLL2, DLL3
ILOAD [DLL1] [DLL1] [DLL3] ... 

REM 填充一段内存空间, 按 FORMAT 给出的指定格式 如"*1*2*4+8*S" 按 1字节, 2字节, 4字节, 指针+8, 字符串型 填充 PTR地址空间, 后边的ARG... 就是填充的 对应类型数据
IFILL [PTR] [FORMAT] [ARG1] [ARG2] [ARG3] ...

REM 将一段内存空间的数据, 按 FORMAT 给出的指定格式 如"*1*2*4+8*S" 按 1字节, 2字节, 4字节, 指针+8, 字符串型 输出到 后边对应的VAR...变量名中
IOUT  [PTR] [FORMAT] [VAR1] [VAR2] [VAR3] ...

REM 将指定参数ARG... 按FORMAT格式 打印到 VAR变量名中 类似C语言中的sprintf
ISET [VAR] [FORMAT] [ARG1] [ARG2] [ARG3] ...

REM 将指定参数ARG... 按FORMAT格式 打印到 PTR地址空间 等同C语言中的sprintf
ISPR [PTR] [FORMAT] [ARG1] [ARG2] [ARG3] ...

备注: 5个内建函数 均为宽字符版本, 字符串参数均需要加 L 前缀 
