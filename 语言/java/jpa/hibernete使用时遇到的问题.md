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

##### 4. 二级缓存

> 二级缓存是session间共享的，适用于对象数据频繁共享，数据变化频率低。

+ read-only是只读型，缓存不更新，适用于不发生改变的数据，效率最高，事务隔离级别最低。
+ nonstrict-read-write不严格读写型，缓存不定期更新，适用于变化频率低的数据。
+ read-write读写型，缓存在数据变化时触发更新，适用于变化的数据。

+ transactional事务型，缓存在数据变化时更新，并且支持事务，效率最低，事务隔离级别最高。

**5. 问题:**

+ 使用findById查出来以后更新没有更新到，过去使用findOne可以更新到
+ 使用getOne报no-session错误
+ 在实体copy后想要用，必须**flush()**
+ 必须使用**EAGER**，才能在复制方法中复制关联对象
+ 一对多多对一关系永远维护在多的一端，如果双向关联，外键可以设置不为空，因为保存时就已经把外键加入了，如果是一对多单向关联，外键必须设置可以为空，因为外键关系是实体保存后更新进去的，另外不仅需要将多的一端手动添加到一的一端的集合里，多的一端也需要手动set一的一端
+ 报序列化错误是实体里某一个属性的类型hibernete自动解析不了