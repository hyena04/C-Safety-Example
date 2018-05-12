# 宏

## 宏不是函数

针对如下代码

```C
#define abs(x) x > 0 ? x : -x

abs(a-b);
```

就会存在问题,被拓展展开为

```C
a-b>0?a-b:-a-b
```

-a-b 不是我们期望的 -(a-b)

* 使用规范

使用宏的时候要给每个参数使用括号

```C
#define abs(x) (x) > 0 ? (x) : -(x)
```

或者

不使用宏实现函数功能,使用内联函数

```C
inline int abs(int x){
    return x > 0 ? x : -x;
}
```

## 宏不是类型定义

针对如下代码

```C
#define T1 struct foo *
typedef struct foo *T2;

T1 a,b;
T2 c,d;
```

表面上 a b c d 四个变量的类型是相同的

但是宏却被拓展为

```C
struct foo * a, b;
```

那么 a 便是一个指针类型

而 b 便是一个结构体

* 使用规范

所以不要宏作为类型

使用 typedef

## 何时使用宏

* 防止头文件被多重包含

在所有头文件中都是用 #define 来防止头文件被多重包含

例如针对 foo/src/bar/baz.h

```C
#ifndef FOO_BAR_BAZ_H_
#define FOO_BAR_BAZ_H_
...
#endif // FOO_BAR_BAZ_H_
```

* 编译时执行情况的确定

例如针对同一个项目可能会有 Debug 或 Release 模式

对 gcc -D DEBUG 对程序进行 DEBUG 模式

```C
    help();
#ifdef DEBUG
    perror("You must give a could be opened .c file\n");
#endif  // DEBUG
    error(__FILE__, __FUNCTION__, __LINE__);
```

DEBUG 模式下才会执行 perror 输出调试信息
