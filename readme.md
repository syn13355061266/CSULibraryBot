# 使用方法：

1. 安装依赖库，命令行运行：pip install -r .\requirements.txt
2. 在 config.py 中填写学号、密码
3. 在 main.py 中根据提示输入想要预约的区域代号
4. 运行 main.py

## P.S 仅对新校和本部的座位进行的梳理 铁道和湘雅... 待开发 orz

## qq 预约机器人整不动了 考完试再整

## 座位号解析 X F7 A 089 → 新校 七楼 A 区 89 号

## 座位号解析 B F2 B 139 → 本部 二楼 B 区 139 号

## 输入字符串示例：

### demo1 = 'X' # 蹲着预约新校所有区域

### demo2 = 'XF5' # 蹲着预约新校五楼

### demo3 = 'XF5A' # 蹲着预约新校五楼 A 区

### demo4 = 'XF5A XF7A BF2B' # 蹲着预约新校五楼 A 区、七楼 A 区 本部二楼 B 区 ### today=True 指定约今天

### today=False 指定约明天
