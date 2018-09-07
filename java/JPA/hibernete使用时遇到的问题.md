**1. SpringJPA中getOne()与findById()区别:**

| getOne()                          | findById()                        |
| --------------------------------- | --------------------------------- |
| Lazily loaded reference to target entity | Actually loads the entity for the given id |
| Useful only when access to properties of object is not required | Object is eagerly loaded so all attributes can be accessed   |
| Throws EntityNotFoundException if actual object does not exist at the time of access invocation | Returns null if actual object corresponding to given Id does not exist |
| Better performance | An additional round-trip to database is required |

https://www.javacodemonk.com/post/87/difference-between-getone-and-findbyid-in-spring-data-jpa

**2. getOne()底层使用的getReference()与findById()底层使用的find()的区别:**

> EntityManager.find() vs EntityManager.getReference()

https://stackoverflow.com/questions/1607532/when-to-use-entitymanager-find-vs-entitymanager-getreference-with-jpa

**3. hibernetes实体实例生命周期与各种状态:**

持久化生命周期/实体实例状态

+ 从瞬时（Transient）状态到持久化状态，从而变成orm托管的，需要调用EntityManager#persist()方法，或者创建来自一个已持久化实例的引用以及为所映射关联启用状态级联（Cascade）。
+ 持久化状态的实体实例具有一个表示形式，它被存储在数据库中，或者在工作单元完成时被存储。什么时候是工作单元完成？这要结合持久化上下文。

**4. 问题:**

+ 使用findById查出来以后更新没有更新到，过去使用findOne可以更新到

+ 使用getOne报no-session错误
+ 在实体copy后想要用，必须**flush()**
+ 必须使用**EAGER**，才能在复制方法中复制关联对象