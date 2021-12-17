from library import main


if __name__ == '__main__':
    # 仅对新校和本部的座位进行的梳理 铁道和湘雅... 待开发orz
    # 座位号解析 X F7 A 089  → 新校 七楼 A区 89号
    # 座位号解析 B F2 B 139  → 本部 二楼 B区 139号
    demo1 = 'X'  # 蹲着预约新校所有区域
    demo2 = 'XF5'  # 蹲着预约新校五楼
    demo3 = 'XF5A'   # 蹲着预约新校五楼A区
    demo4 = 'XF5A XF7A BF2B'  # 蹲着预约新校五楼A区、七楼A区 本部二楼B区
    demo = 'X'  # 输入字符串
    main(demo, today=False)
    # today=True 指定约今天
    # today=False 指定约明天
