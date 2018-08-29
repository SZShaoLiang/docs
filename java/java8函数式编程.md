#### 1. 什么是Lambda(λ)表达式

在数学运算和一般计算中，lambda表达式是一个函数：对于某些输入值或者所有的输入值，有确定的输出值。java使用lambda表达式为自己引入了函数(java只支持方法)。使用传统的java术语解释，lambda可以被理解为具有更简洁语法的匿名方法，这个匿名方法可以省略修饰符，返回类型，某些情况下，参数类型也可以省略。

+ lambda语法

  ```
  (parameters) -> expression
  (parameters) -> { statements; }
  ```

+ 例子

  ```java
  // 输入两个整数，返回他们的和
  1. (int x, int y) -> x + y
  // 输入两个值，返回他们的差
  2. (x, y) -> x - y 
  // 没有输入，返回42
  3. () -> 42
  // 输入一个字符串，打印他到控制台，返回为空
  4. (String s) -> System.out.println(s)
  // 输入一个值，返回doubling x
  5. x -> 2 * x 
  // 输入一个collection，清空他，并返回清空前的size
  6. c -> { int s = c.size(); c.clear(); return s; }
  ```

+ 语法说明

  + 参数类型可以显示声明（如1、4）或者隐式推断（如2、5、6）。声明和推断不能在单个lambda表达式中混合使用。
  + body可以是代码块（使用大括号包裹，如6）或者表达式（如1、5）。代码块可以有返回值也可以什么都不返回（与void兼容）。
  + 如果body是一个表达式，他只能**返回一个值**（如1、2、3、5）或什么都不返回。
  + 如果只有一个隐式推断类型的参数，可以省略括号（如5、6）。
  + 对于例子6，意味着lambda可以用在collection上，因为collection实现了Function接口。那么同样的，如果还有一个类实现了Function接口，且实现了相同参数和返回类型的size和clear方法，那lambda表达式如何区分当前的c是collection呢，这里是根据代码的上下文来做推断的。

#### 2. 为什么将lambda表达式添加到java？

Lambda表达式（闭包）是许多现代编程语言的时髦特征。抛开为了时髦，java引入lambda表达式最紧迫的原因是简化在多线程中集合的分发处理。在之前，lists和sets的处理通常由java开发人员自己从collection中获取一个iterator，然后使用iterator迭代并处理每一个元素。如果想要并行处理，只能由java开发人员自己写并行逻辑。

在java8中，我们的目的是不再是collection为开发人员提供方法，而是开发人员为collection提供函数，并使用函数来对collection中的元素做处理。此更改带来的优势是collection现在可以在内部组织自己的迭代，同时也可以处理并行化，这样就将并行处理的责任从开发人员转移到了java类库中。

但是，开发人员想要利用这一点，需要有一种向collection提供函数的简单方法。在lambda之前，执行此操作的标准做法是传入适当的匿名类实现。但是，定义匿名内部类的语法太过笨拙，无法实现简单的目的。

例如，collection上的forEach方法获取Consumer接口的实例并为每一个元素调用accept方法：

```java
interface Consumer<T> { void accept(T t); }
```

假设我们想要用forEach转置每个Point的坐标x和y。使用匿名内部类实现，我们将使用Consumer传递转置函数，如下：

```java
pointList.forEach(new Consumer<Point>() {
    public void accept(Point p) {
        p.move(p.y, p.x);
    }
});
```

如果使用lambda，可以十分简洁的实现相同的效果：

```java
pointList.forEach(p -> p.move(p.y, p.x));
```

#### 3. 什么是functional interface（函数式接口）?

> Informally, a functional interface is one whose type can be used for a method parameter when a lambda is to be supplied as the actual argument.

非正式的讲，当函数式接口被一个lambda实现时，他可以被作为一个方参数传入到方法中，这个参数的类型就是functional interface.

例如，collection中的forEach方法的方法签名如下：

```java
public void forEach(Consumer<? super T> consumer);
```

要使用forEach方法必须实现Consumer中的单个方法。这个实现可能是一个lambda表达式；如果是，这个表达式就被应用到调用这个方法的地方。以这种方式，lambda表达式只能替换一个接口方法。因此，接口只有单个方法时（不包括default、static修饰的方法以及覆写Object的方法），才能使用lambda表达式实现接口而且不产生歧义。

更确切的说，函数式接口被定义为恰好有一个显式声明的抽象方法的接口。这就是为什么函数式接口在过去被称为单抽象方法(ASM)接口，这个术语有时仍然可见。

+ 例子

  java类库中有如下（部分常见）是根据上述定义的函数式接口：

  ```java
  public interface Runnable { void run(); } 
  public interface Callable<V> { V call() throws Exception; } 
  public interface ActionListener { void actionPerformed(ActionEvent e); } 
  public interface Comparator<T> { int compare(T o1, T o2); boolean equals(Object obj); } 
  ```

+ 语法

  + Comparator接口有两个抽象方法，但其中一个equals方法是覆写了Object的equals方法。接口总是声明对应于Object公共方法的抽象方法，但它们通常是隐含的。无论是隐式声明还是显式声明，此类方法都会从计数中排除。
  + [跳过]有一种情况下会变得复杂，由于两种接口可能具有不完全相同的方法，但由于擦除而相关。（*override-equivalent*）

#### 4. lambda表达式的类型是什么？

Lambda表达式是函数式接口的实例。但lambda表达式本身并不包含他正在实现哪个函数式接口的信息；该信息是从使用他的上下文中推导出来的。例如：

```
x -> 2 * x
```

上面表达式可以是下面函数式接口的实例

```java
interface IntOperation { int operate(int i); }
```

所以合法的写法是

```java
IntOperation iop = x -> 2 * x
```

此处期望表达式的类型式IntOperation，这称为lambda表达式的目标类型。但lambda表达式可以与不同的函数式接口类型兼容，因此同样的lambda表达式可以在不同的上下文中具有不同的目标类型。例如，给定一个接口

```java
interface DoubleOperation { double operate(double i); }
```

下面代码也是合法的

```java
DoubleOperation dop = x -> 2 * x
```

总结一下，lambda表达式的目标类型必须是函数接口，并且为了与目标类型兼容，lambda表达式必须与函数式接口具有相同的参数类型，其返回类型必须与接口返回类型兼容，并且只能抛出接口允许的异常。 

#### 5. lambda表达式是对象吗？

是的，但不完全是：他们是Object子类的实例，但不一定具有唯一的标识。lambda表达式是函数式接口的一个实例，他本身就是Object的子类。如下可以看出这一点：

```java
Runnable r = () -> {};
Object o = r;
```

为了理解这种情况，有必要知道Java 8中的实现既有短期目标，也有长期目标。短期目标是为了支持日益并行的硬件而实现collection的内部迭代。从长远来看，是为了Java能够支持更多函数式风格的编程。目前只追求短期目标，但设计人员正谨慎的地避免损害Java函数式编程的未来，这可能在未来包括完整的函数类型，例如Scala和Haskell。

#### 6. lambda表达式可以在哪里使用？

Lambda表达式可以在具有目标类型的任何上下文中使用。具有目标类型的上下文有下面特征：

+ 声明的变量、赋值、已经初始化的数组，这时目标类型为指定的类型或者数组类型。

+ 返回语句，目标类型为方法期望的返回类型。

+ 方法或者构造函数的参数，目标类型为相应参数的类型。如果方法后者构造函数被重载，编译器会先执行重载决策，然后给出目标类型。如果重载决策和类型推断后还有歧义，则可以显式的提供目标类型。

+ lambda表达式主体，通过派生，lambda表达式本身可以提供目标类型为他们的主体，这也是可以在函数中返回函数的关键，例如：

  ```java
  Supplier<Runnable> c = () -> () -> { System.out.println("hi"); };
  ```

+ 三元条件表达式，例如：

  ```java
  Callable<Integer> c = flag ? (() -> 23) : (() -> 42);
  ```

+ 强制转换，显式的提供目标类型，例如：

  ```java
  // Runnable或者Callable都有可能
  Object o = () -> { System.out.println("hi"); };	
  // 强制转换消除了歧义，所以合法
  Object o = (Runnable) () -> { System.out.println("hi"); }
  ```

#### 7. lambda表达式的作用域

Lambda表达式不从超类型继承任何变量名称，也不引入新级别的作用域。除了lambda表达式为自己的形参添加了新名称，lambda表达式主体中的名称与封闭环境中的名称完全相同，主体中的this和super关键字也和表达式主体之外的一样。

```java
public class Hello {
  Runnable r1 = () -> { System.out.println(this); }
  Runnable r2 = () -> { System.out.println(toString()); }

  public String toString() { return "Hello, world!"; }

  public static void main(String... args) {
    new Hello().r1.run();
    new Hello().r2.run();
  }
}
```

上面的例子中打印了两次”Hello, world!“。

同时这也意味着：

+ 可以直接在lambda表达式中访问外层的局部变量
+ 在lambda表示中不可以修改外层局部变量
+ 在lambda表达式中声明变量不容许与局部变量同名
+ Lambda内部对于成员变量以及静态变量是即可读又可写。

#### 8. 业务上常用到lambda的地方

+ JPA以及Entity和DTO之间频繁的Mapper。

  我们在使用Spring JPA时，仓储（Repository）继承JpaRepository；JPA提供的findById查询会返回Optional\<T>，Optional中的大部分方法参数类型都是函数式接口，所以Optional方法可以传入lambda表达式。例如：

  ```java
  // 删除先找后删，通过JPA提供的findById方法，获得一个Optional<Role>,
  // 调用Optional的ifPresent方法，表示如果找到Role，就执行方法中的lambda表达式，
  // 如果没有找到，就什么也不做。
  roleRepository.findById(id).ifPresent((role) -> roleRepository.delete(role));
  // 可以用双冒号（方法参考符）将方法调用简写为下面
  roleRepository.findById(id).ifPresent(roleRepository::delete);
  ```

  思考下面的代码：

  ```java
  // 下面是RoleController里的一段代码，意思是如果Optional中Role不为null，就返回Role，状态码为200
  // 如果Role为null，也不会报空指针异常，而是会返回状态码404。
  // 注意：此处为示例代码，实际业务中禁止在controller层直接调用repository层。
  public ResponseEntity<Role> getUserById(@PathVariable String id) {
          logger.debug("REST request to get User : {}", id);
          return ResponseUtil.wrapOrNotFound(roleRepository.findById(id));
  }

  <X> ResponseEntity<X> wrapOrNotFound(Optional<X> maybeResponse, HttpHeaders header) {
          return maybeResponse.map(response -> ResponseEntity.ok().headers(header).body(response))
              .orElse(new ResponseEntity<>(HttpStatus.NOT_FOUND));
  }
  ```

  另外JPA提供的findAll方法会返回Page\<T>或者List\<T>，他们的方法都可以传入lambda表达式。

  ```java
  // findAll返回一个Page<User>，使用map方法传入lambda表达式，将返回Page<UserDTO>。
  userRepository.findAll(specifications, pageable).map(new UserMapper()::userToUserDTO);
  ```

  ​

+ 集合的处理（stream）。

  ```java
  // userDTO.getAuthorities()返回的是一个Set<String>，代表roleId的集合
  Set<Role> authorities = userDTO.getAuthorities().stream().map(roleRepository::getOne).collect(Collectors.toSet());
  ```

  关于stream，这里不多讲，是另一大块的内容，总之，collection可以转化为stream，而流里的方法都可以接收lambda表达式，最后处理完成后再转回collection。

#### 9. 杂项

延伸阅读:

[lambda-state-final](http://cr.openjdk.java.net/~briangoetz/lambda/lambda-state-final.html)

延伸思考：

方法和函数的区别？

多CPU、多核、超线程的关系？

单核多线程与多核多线程的区别？

什么是闭包，什么是匿名方法，java里的闭包？

为什么函数式编程适合多核时代？

go语言为什么比java更支持高并发？

go语言多返回值与柯里化？

多线程与异步的区别？

**本文来源**：本文翻译自http://www.lambdafaq.org/，仅供学习使用，转载请注明出处:https://github.com/fallingyang/docs。