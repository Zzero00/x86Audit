# 简介

IDA x86_64静态扫描脚本，汇编审计辅助脚本，参考mipsAudit@giantbranch：https://github.com/giantbranch/mipsAudit

使用的是python2，当前测试得较少，不完善之处请指正

# 使用

拿到py文件之后放在同一目录下，ida里面选择`File`-->`Script file`，如下：

![image-20211210171106426](README/image-20211210171106426.png)



然后选择`x86Audit.py`即可

# 功能



同mipsAudit，辅助脚本功能如下：

1. 找到危险函数的调用处，并且高亮该行
2. 给参数赋值处加上注释
3. 最后以表格的形式输出函数名，调用地址，参数，字符串提示，还有当前函数的缓冲区大小

双击addr等可进行跳转：

![image-20211210171621139](README/image-20211210171621139.png)

![image-20211210171639935](README/image-20211210171639935.png)

## 审计的危险函数

如下：

```
dangerous_functions = [
    "strcpy", 
    "strcat",  
    "sprintf",
    "read", 
    "getenv"    
]

attention_function = [
    "memcpy",
    "strncpy",
    "sscanf", 
    "strncat", 
    "snprintf",
    "vprintf", 
    "printf"
]

command_execution_function = [
    "system", 
    "execve",
    "popen",
    "unlink"
]
```

# 效果

![image-20211210180837096](README/image-20211210180837096.png)

strcpy函数：

![image-20211210180857617](README/image-20211210180857617.png)

read函数：

![image-20211210180911109](README/image-20211210180911109.png)

printf函数：

![image-20211210180952259](README/image-20211210180952259.png)

system函数：

![image-20211210181021170](README/image-20211210181021170.png)