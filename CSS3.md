title: 文章标题
date: 2017年1月1日 0时:0分:0秒 #创建时间，可加时区如" +0800"
update: 2017年1月1日 0时:0分:0秒 #更新时间，可选，可加时区如" +0800"
author: 作者ID
cover: 题图链接 #可选
draft: false #草稿，可选
top: false #置顶文章，可选
preview: 文章预览，也可在正文中使用<!--more-->分割 #可选
tags: #可选
    - 标签1
    - 标签2

---

显示多行：
```
    .pro-list .pro-brief-title{line-height: 1.3em;height: 2.6em;overflow: hidden;
    /* 新属性 */text-overflow:ellipsis;-webkit-line-clamp:2;display: -webkit-box;-webkit-box-orient:vertical;}
```

显示一行：
```
    .pro-list .pro-brief-title{line-height: 1.3em;height: 2.6em;overflow: hidden;white-space:nowrap;
    /* 新属性 */text-overflow:ellipsis;}
```
