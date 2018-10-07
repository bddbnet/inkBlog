title: JWT 扩展具体实现详解

date: 2017-06-06 01:02:03
update: 2017-06-06 01:02:03
author: me

tags: 
    - laravel
    - jwt
    - php
    
   

---

> 转载 [https://laravel-china.org/articles/10889/detailed-implementation-of-jwt-extensions]()

> 2018/10/4：

> 主要更新了中间件的区别那一部分，推荐使用 jwt.auth 中间件，虽然官网用的是 auth:api ，但是 jwt.auth 有着更加丰富的返回信息。


`tymon/jwt-auth` 扩展是 Laravel 下能够很方便的实现 JWT token 的一个扩展，使用和配置都很简单，但是网上的文档新版本的、旧版本的掺杂在一起，看起来十分混乱，因此我仔细比对源码整理了一个比较完整的安装文档：[JWT 完整使用详解](https://laravel-china.org/articles/10885/full-use-of-jwt) 。

看源码的过程中对这个扩展和 Laravel 的一些实现也有了比较深入的理解，记录如下。

# 参考资料
- [Laravel 认证原理及完全自定义认证](https://laravel-china.org/articles/3825/laravel-authentication-principle-and-full-custom-authentication)
> Tips：最好打开框架和扩展中的源代码放一边参考，这样更利于理解，每个文件的路径和命名空间基本一致。

## 一、看守器
### 1. 契约
看守器 Guard 是一组契约（不懂的话就看成接口吧），定义了一些认证和登录的常用方法。

**Illuminate\Contracts\Auth\Guard**

这个看守器定契约义了如下方法，而 JWT 的看守器便是实现了这个接口，所以 JWT 的看守器就会具有这些方法，当然 JWT 的看守器还并不止这些方法，这个后面再仔细说。
```
// 判断当前用户是否登录
public function check();
// 判断当前用户是否是游客（未登录）
public function guest();
// 获取当前认证的用户
public function user();
// 获取当前认证用户的 id，严格来说不一定是 id，应该是上个模型中定义的唯一的字段名
public function id();
// 根据提供的消息认证用户
public function validate(array $credentials = []);
// 设置当前用户
public function setUser(Authenticatable $user);
```

**Illuminate\Contracts\Auth\StatefulGuard**

StatefulGuard 接口继承自 Guard 接口，并添加了一些新的有状态的方法。

看到 attempt 方法，可能有人就会觉得 JWT 的看守器似乎好像有理由是由这个继承而来，然后代码告诉我们，并非如此。
```
// 尝试根据提供的凭证验证用户是否合法
public function attempt(array $credentials = [], $remember = false);
// 一次性登录，不记录session or cookie
public function once(array $credentials = []);
// 登录用户，通常在验证成功后记录 session 和 cookie 
public function login(Authenticatable $user, $remember = false);
// 使用用户 id 登录
public function loginUsingId($id, $remember = false);
// 使用用户 ID 登录，但是不记录 session 和 cookie
public function onceUsingId($id);
// 通过 cookie 中的 remember token 自动登录
public function viaRemember();
// 登出
public function logout();
```

### 2. 对契约的实现
有了契约之后就要实现契约了，Laravel 框架自己针对上述契约实现了三个看守器类。

**Illuminate\Auth\RequestGuard**

实现了 Guard ，这里面的方法非常简单，大概就契约里约定的那么多，而且有一部分复用 GuardHelpers 这个 trait 来实现的。

**Illuminate\Auth\SessionGuard**

实现了 StatefulGuard，是 Laravel web 认证默认的 guard，定义了完整的 session 方式登录实现。

**Illuminate\Auth\TokenGuard**

实现了 Guard，适用于无状态 api 认证，通过 token 认证。但这里面实现的方法也挺少的，你可以根据这个实现一个简单的 token 认证。

**Tymon\JWTAuth\JWTGuard**

然后主角登场了，JWTGuard 实现了 Guard，和上面的三个实现是同级的，你可以理解为，官方的 TokenGuard 功能太简单，这个扩展写了一个比 TokenGuard 功能更加丰富的 Guard。

### 3. Gurad 的使用
好，我们现在已经知道 Guard 是什么一个东西已经它的实现了，那怎么使用呢？打开下面文件：

**/config/auth.php**
```
// 这里是指定默认的看守器
// web 的意思取下面 guards 数组 key 为 web 的那个
// passwords 是重置密码相关，暂时不懂什么意思
'defaults' => [
    'guard' => 'web',
    'passwords' => 'users',
],

// 这里定义可以用的 guard
// driver 指的就是上面的对 Guard 契约的具体实现那个类了
// users 是下面 providers 数组 key 为 users 的那个
'guards' => [
    'web' => [
        'driver' => 'session',  // SessionGuard 实现
        'provider' => 'users',  
    ],

    'api' => [
        'driver' => 'jwt',  // JWTGuard 实现，源码中为 token，我这改成 jwt 了
        'provider' => 'users',
    ],
],

// 这个的作用是指定认证所需的 user 来源的数据表
'providers' => [
    'users' => [
        'driver' => 'eloquent',
        'model' => App\User::class,
    ],

    // 'users' => [
    //     'driver' => 'database',
    //     'table' => 'users',
    // ],
],
```

> 通过以上你就知道了：

> 1. 认证用的那些方法是通过实现了 Guard 契约，契约保证了框架与扩展之间的低耦合性，为什么这样可以低耦合，后面中间件和辅助函数会具体介绍
> 2. JWT 的 JWTGuard 实现了 Guard 契约
> 3. 定义的 Guard 如何具体使用


# 二、中间件
看 JWT 的文档，里面定义的 AuthController 方法使用的是 auth:api 中间件，而 JWT 还提供了 jwt.auth 和 `jwt.refresh` 中间件，那么这些中间件有什么不同又是如何起作用的呢？

## 1. 定义
### 1.1 app\Http\Kernel.php

```
// 这里是指定默认的看守器
// web 的意思取下面 guards 数组 key 为 web 的那个
// passwords 是重置密码相关，暂时不懂什么意思
'defaults' => [
    'guard' => 'web',
    'passwords' => 'users',
],

// 这里定义可以用的 guard
// driver 指的就是上面的对 Guard 契约的具体实现那个类了
// users 是下面 providers 数组 key 为 users 的那个
'guards' => [
    'web' => [
        'driver' => 'session',  // SessionGuard 实现
        'provider' => 'users',  
    ],

    'api' => [
        'driver' => 'jwt',  // JWTGuard 实现，源码中为 token，我这改成 jwt 了
        'provider' => 'users',
    ],
],

// 这个的作用是指定认证所需的 user 来源的数据表
'providers' => [
    'users' => [
        'driver' => 'eloquent',
        'model' => App\User::class,
    ],

    // 'users' => [
    //     'driver' => 'database',
    //     'table' => 'users',
    // ],
],
```
> 通过以上你就知道了：

> 1. 认证用的那些方法是通过实现了 Guard 契约，契约保证了框架与扩展之间的低耦合性，为什么这样可以低耦合，后面中间件和辅助函数会具体介绍
> 2. JWT 的 JWTGuard 实现了 Guard 契约
> 3. 定义的 Guard 如何具体使用


# 二、中间件
看 JWT 的文档，里面定义的 AuthController 方法使用的是 auth:api 中间件，而 JWT 还提供了 jwt.auth 和 `jwt.refresh` 中间件，那么这些中间件有什么不同又是如何起作用的呢？

## 1. 定义
### 1.1 框架的中间件
**app\Http\Kernel.php**

这个文件中定义了框架自带的中间件：
```
protected $routeMiddleware = [
        'auth' => \Illuminate\Auth\Middleware\Authenticate::class,
        'auth.basic' => \Illuminate\Auth\Middleware\AuthenticateWithBasicAuth::class,
        'bindings' => \Illuminate\Routing\Middleware\SubstituteBindings::class,
        'cache.headers' => \Illuminate\Http\Middleware\SetCacheHeaders::class,
        'can' => \Illuminate\Auth\Middleware\Authorize::class,
        'guest' => \App\Http\Middleware\RedirectIfAuthenticated::class,
        'signed' => \Illuminate\Routing\Middleware\ValidateSignature::class,
        'throttle' => \Illuminate\Routing\Middleware\ThrottleRequests::class,
];
```

**auth:api**

可以发现 `auth:api` 使用的就是第一个中间件，而后面 `:api` 是路由参数，指定了要使用哪个看守器，可以看到下面 `api` 对应的看守器就是 `jwt` 的看守器。

并且你可以直接使用 auth ，这样就相当于使用 defaults 中指定的看守器，即 session。

> Lumen 默认用的就是 api 那个，所以你直接用 auth 作为 api 路由的中间件完全没问题

> Laravel 中指定了两个看守器，而且默认的并不是 api，所以你必须得用 auth:api 作为路由的中间件

功能是检查 token 的有效性，决定是否放行。

**/config/auth.php**
```
'defaults' => [
    'guard' => 'web',
    'passwords' => 'users',
],

'guards' => [
    'web' => [
        'driver' => 'session',  // SessionGuard 实现
        'provider' => 'users',  
    ],

    'api' => [
        'driver' => 'jwt',  // JWTGuard 实现，源码中为 token，我这改成 jwt 了
        'provider' => 'users',
    ],
]
```

### 1.2 jwt-auth 的中间件
**tymon\jwt-auth\src\Providers\AbstractServiceProvider.php**
```
protected $middlewareAliases = [
    'jwt.auth' => Authenticate::class,
    'jwt.check' => Check::class,
    'jwt.refresh' => RefreshToken::class,
    'jwt.renew' => AuthenticateAndRenew::class,
];
```

这个文件中定义了 jwt-auth 插件的中间件，第一二个功能一样，只是第二个不会主动抛出错误，第三四个功能一样。

**jwt.auth**
这个和上面的功能完全一致，至于有什么区别后面会具体解释。

**jwt.refresh**
这个出来检验 token 的有效性并决定如何放行外，还会在返回的 header 头上加入新的 token，达到每次请求都换取新 token 的效果。

## 2. 使用
使用就不多说了，官方文档介绍的很详细了。
```
$this->middleware('auth:api', ['except' => ['login']]);
```

## 3. 区别
接下来就探讨一下，这三个中间件有什么区别。

### 3.1 jwt.refresh 和 jwt.auth
这个的区别就是前者会在响应的 header 头中增加刷新的新 token。

### 3.2 jwt.auth 和 auth:api（auth）
这两个功能完全一致，只是调用链有所差别，而这个差别正好可以体现上面提到的低耦合性。

**auth:api（auth）**
Illuminate\Auth\Middleware\Authenticate
```
use Illuminate\Contracts\Auth\Factory as Auth;

public function __construct(Auth $auth)
{
    $this->auth = $auth;
}

public function handle($request, Closure $next, ...$guards)
{
    $this->authenticate($guards);

    return $next($request);
}

protected function authenticate(array $guards)
{
    if (empty($guards)) {
        return $this->auth->authenticate();
    }

    foreach ($guards as $guard) {
        if ($this->auth->guard($guard)->check()) {
            return $this->auth->shouldUse($guard);
        }
    }

    throw new AuthenticationException('Unauthenticated.', $guards);
}
```
Illuminate\auth\GuardHelpers.php
```
public function check()
{
    return ! is_null($this->user());
}

public function authenticate()
{
    if (! is_null($user = $this->user())) {
        return $user;
    }

    throw new AuthenticationException;
}
```

可以看到：

1. 路由参数作为参数传入 handle 方法，然后调用下面的 authenticate 方法；
2. authenticate 根据所给的参数选择进行校验的 guard ，然后通过 guard 进行校验，如果校验不通过则统一抛出 AuthenticationException
**jwt.auth**
Tymon\JWTAuth\Middleware\Authenticate
```
public function handle($request, Closure $next)
{
    $this->authenticate($request);

    return $next($request);
}
```
Tymon\JWTAuth\Middleware\BaseMiddleware
```
public function authenticate(Request $request)
{
    $this->checkForToken($request);

    try {
        if (! $this->auth->parseToken()->authenticate()) {
            throw new UnauthorizedHttpException('jwt-auth', 'User not found');
        }
    } catch (JWTException $e) {
        throw new UnauthorizedHttpException('jwt-auth', $e->getMessage(), $e, $e->getCode());
    }
}
```
可以看到：

1. 路由参数作为参数传入 handle 方法，然后调用下面的 authenticate 方法；
2. authenticate 直接用自身逻辑进行校验，然后抛出错处，与前面不同的是，这里抛出的错误种类更加丰富，因此我推荐还是使用这个中间件比较好。


## 三、辅助函数和 Facade
### 1. 辅助函数
辅助函数是 Laravel 提供的一系列函数，可以很方便的做到一些事情，这里要提到的是 auth()

使用这个函数报错的，是因为你用的是 Lumen ，而 Lumen 阉割了这个函数，你可以通过安装扩展补齐。

**auth()**
`auth` 函数返回一个 [认证](https://laravel-china.org/docs/laravel/5.6/authentication) 实例。为了方便起见，你可以使用它来替代 Auth Facade：

$user = auth()->user();
如果需要，你可以指定你想要访问的认证实例：

$user = auth('admin')->user();
> 以上是官方文档对于此辅助函数的解释。

接下来我要一句话解释上面这个辅助函数，你可以仔细品味这句话直到理解为止：

> auth() 返回的一个看守器实例，如上面的 SessionGuard 和 JWTGuard ，然后你就可以链式调用对于看守器提供的所有方法，此外这个函数的参数可以指定所要返回的看守器实例，否则返回默认的，例如 auth('api')。


```
'guards' => [
    'web' => [
        'driver' => 'session',  // SessionGuard 实现
        'provider' => 'users',  
    ],

    'api' => [
        'driver' => 'jwt',  // JWTGuard 实现，源码中为 token，我这改成 jwt 了
        'provider' => 'users',
    ],
]
```

#### JWT 下的 auth()
安装 JWT 后，你可以在 auth() 后面调用 factory() 或 payload() 之类的来调用更多定义的方法。（看了源代码没看懂是怎么实现的，可能是 __call 魔术方法），可用的有下面这些：

**auth()->factory()**
**auth()->blacklist()**
**auth()->manager()**
**auth()->payload()**


使用示例：
```
$exp = auth()->payload()->get('exp');
$json = auth()->payload()->toJson();
$array = auth()->payload()->jsonSerialize();
```

更多的方法可以去源代码下看。

### 2. Facade
config/app.php
```
'aliases' => [
    ...
    'JWTAuth' => 'Tymon\JWTAuth\Facades\JWTAuth',
    'JWTFactory' => 'Tymon\JWTAuth\Facades\JWTFactory',
],
```

Facade 可以为你的编程带来一点便利，具体的使用我在 Laravel/Lumen教程4-JWT的基本使用 一文中有详细介绍，这里展示一个小的使用示例：
```
/**
 * Get the guard to be used during authentication.
 * 这个和方法和辅助函数 auth() 差不多，如果 Lumen 不想用插件补充 auth()，可以这么写
 *
 * @return \Illuminate\Contracts\Auth\Guard
 */
public function guard()
{
    return JWTAuth::guard();
}
```

> 此外 Auth:: 这个 Facade 也是返回一个看守器实例，当成辅助函数 auth 使用就好了。





