title: Linux下phpStorm等等jetbrains编辑器无法使用搜狗输入法输入中文
date: 2017-06-06 01:02:03
update: 2017-06-06 01:02:03
author: admin

tags: 
    - jetbrains
    - 编辑器
    - 中文
   

---

#### 安装fcitx等软件

```bash
sudo apt install fcitx fcitx-config-gtk fcitx-bin fcitx-frontend-gtk2 fcitx-frontend-gtk3 
fcitx-frontend-qt4 fcitx-frontend-qt5 fcitx-libs fcitx-modele-dbus fcitx-module-kimpanel fcitx-module-x11 fcitx-modules fcitx-ui-classic
```


#### 修改phpstorm启动文件
```
cd .local/share/JetBrains/Toolbox/apps/PhpStorm/ch-0/181.5281.35/bin
vim phpstorm.sh 
```
在 Run the IDE.的注释之前添加
```
export XMODIFIERS="@im=fcitx"
export GTK_IM_MODULE="fcitx"
export QT_IM_MODULE="fcitx"
```

#### 使用 `im-config` 配置输入法

控制台输入 `im-config`
ok,yes,fcitx,ok,ok
重启x桌面或者直接重启电脑





