title: Css3 文字省略号...
date: 2017-01-01 01:01:01 
update: 2017-01-01 01:01:01 
author: me
tags: 
    - css3
    - css

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
