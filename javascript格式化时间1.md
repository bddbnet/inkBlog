title: javascript格式化时间（几秒钟前，几分钟前，几小时前，几天前...）
date: 2017-06-06 01:02:03
update: 2017-06-06 01:02:03
author: admin

tags: 
    - javascript
   

---

> 将时间转换为 几秒钟前，几分钟前，几小时前，几天前…

```
/** 
 * 人性化时间处理 传入时间
 * 例如  beautify_time('2018-09-26 15:43:38') 
 * 返回  22秒前
 */
function beautify_time(datetime) {

    var mistiming = Math.round(new Date() - new Date(datetime).getTime() );
        var postfix = mistiming > 0 ? '前' : '后'
        mistiming = Math.abs(mistiming/ 1000) 
        var arrr = ['年', '个月', '星期', '天', '小时', '分钟', '秒'];
        var arrn = [31536000, 2592000, 604800, 86400, 3600, 60, 1];

        for (var i = 0; i < 7; i++) {
            var inm = Math.floor(mistiming / arrn[i])
            if (inm != 0) {
                return inm + arrr[i] + postfix
            }
        }
    }
```
