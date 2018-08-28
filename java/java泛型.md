#### 范型方法(GENERIC METHOD)

```java
[权限] [修饰符] [泛型] [返回值] [方法名]  (    [参数列表]   ) {}
public static  < E >   void   printArray( E[] inputArray ) {}
```

#### 范型类(GENERIC CLASS)

泛型类和普通类的声明一样，只是在类名后面加上了类型表示。就像泛型方法，泛型类可以有一个或多个类型表示，用逗号进行分隔

#### 范型接口(GENERIC INTERFACE)

泛型接口是在声明接口的时候指定，类在继承接口的时候需要补充泛型类型，可以实现泛型接口的时候不指名泛型类型，这样这个类就需要定义为泛型类

#### 类型推导

以声明键值对的例子来说，通常的写法会有一长串，不免有些痛苦

```java
Map<String, List<String>> m = new HashMap<String, List<String>>();
```

在JavaSE1.6之后，可以省略后面的范型

```java
Map<String, List<String>> m = new HashMap<>();
```

还可以构造一个泛型方法作为静态工厂，来完成这一操作

```java
public static <K, V> HashMap<K, V> newInstance() {
  return new HashMap<K, V>();
}
Map<String, List<String>> m = newInstance();
```

#### 泛型标识与泛型通配符

标识规范

```
E - Element (在集合中使用，因为集合中存放的是元素)
T - Type（Java 类）
K - Key（键）
V - Value（值）
N - Number（数值类型）
? - 表示不确定的java类型
S、U、V - 2nd、3rd、4th types
```

任意类型 <?>

> 可以理解为泛型中的 Object，为什么这么说呢？因为任意类型的通配符可以接受任意类型的泛型。

下面的例子表示出了这种关系:

```java
Box<?> box = new Box<String>();
```

类似于将后面的类型转换到前面的类型。但是<?>只能用作接收，不能用来定义。

下面的例子是错误的：

```java
class Box<?> {} //错误的泛型类定义
public static <?> void sayHello(? helloString) {} //错误的泛型方法定义
interface Box<?> {} //错误的泛型接口定义
```

上限类型 <? extends 类>

> <? extends 类> 表示泛型只能使用这个类或这个类的子类。

下限类型 <? super 类>

> 同上限方法，<? super 类> 表示泛型只能使用这个类或这个类的父类

#### 可变参数

```java
public class Main {
  public static <T> void out(T... args) {
    for (T t : args) {
      System.out.println(t);
    }
  }
  public static void main(String[] args) {
    out("findingsea", 123, 11.11, true);
  }
}
```

原文链接：<http://www.qiuchengjia.cn/2016/08/03/JAVA/Java%E6%B3%9B%E5%9E%8B/>