---
title: MySql碎碎念
date: 2017-06-21 19:37:48
tags: mysql
---

#### 1. MySql 逻辑架构

##### 1.1 三层结构

- 最上层不是mysql独有的，大多数基于网络的客户端／服务器的工具或者服务都有类似的架构。比如连接处理、授权认证、安全等等。
- 第二层是MySql比较有意思的部分。大多数MySql的核心服务功能都在这一层，包括查询解析、分析、优化、缓存以及所有的内置函数（例如：日期、时间、数学和加密函数），所有跨存储引擎的功能都在这一层实现：存储过程、触发器、视图等。
- 第三层包含了存储引擎。存储引擎主要负责MySql中数据的存储和提取。不同存储引擎都有各自的优势和劣势。服务器通过API与存储引擎进行通信。这些API屏蔽了不同存储引擎之间的差异，使得这些差异对上层的查询过程透明。存储引擎包含几十个底层函数，用于执行诸如“开始一个事物”或者“根据主键提取一行记录”等操作。但存储引擎不会去解析SQL(除了InnoDB，它会解析外键，因为MySql服务器本身没有实现该功能),不同存储引擎之间也不会相互通信，而只是简单的响应上层服务器的请求。

##### 1.2 连接管理与安全性

每个客户端连接都会在服务器进程中拥有一个线程，这个连接的查询只会在这个单独的线程中执行，该线程只能轮流在某个CPU核心或者CPU中运行。服务器会负责缓存线程，因此不需要为每一个新建的连接创建或销毁线程。

客户端连接服务器需要认证，认证基于用户名、主机信息和密码。也可以使用安全套接字（SSL）的方式连接，还可以使用X.509证书认证，连接成功会验证权限。

##### 1.3 优化与执行

MySql会在解析查询，并创建内部数据结构，然后对其进行优化，包括重写查询、决定表的读取顺序，以及选择合适的索引等。

对于select语句，在解析查询之前会先检查查询缓存。

#### 2.并发控制

> 多个查询需要同一时刻修改数据，都会产生并发控制的问题，并发控制在两个层面，数据库服务器层和存储引擎层。
>
> 尽管存储引擎可以管理自己的锁，MySQL数据库服务器本身还是会使用各种有效的表锁来实现不同的目的。例如：服务器会为诸如ALTER TABLE之类的语句使用表锁，而忽略存储引擎的锁机制。

##### 2.1 读写锁

- 读锁：又叫共享锁，读锁是共享的，或者说是相互不阻塞的，多个客户端可以在同一时刻读取同一个资源，而互不干扰。
- 写锁：又叫排他锁，它是排他的，也就是说一个写锁会阻塞其他的写锁和读锁。
- 写锁比读锁有更高的优先级，一个写锁请求可能会被插入到读锁队列的前面。

##### 2.2 锁粒度

> 申引：锁策略就是在锁的开销和数据的安全性之间寻找平衡，这种平衡也会影响性能。

- 表锁（table lock）

  表锁是MySql中最基本的锁策略，也是开销最小的策略。表锁会锁定整张表。

- 行级锁（row lock）

  行级锁可以最大程度地支持并发处理（同时也带来了最大的锁开销）。InnoDB和XtraDB实现了行级锁。行级锁只在存储引擎层实现，没有在MySql服务器层实现。

#### 3.事务

> 什么是事务？事务的标准特性（ACID）是什么？大家都知道。
>
> 一个实现了ACID的数据库，相比没有实现ACID的数据库，通常会需要更强的CPU、更大的内存和更多的磁盘。

##### 3.1 隔离级别

> 数据库中实现事务隔离有两种方式：一种是读取数据前，对其加锁，阻止其他事务对数据进行修改；另一种是数据库多版本并发控制（MVCC或MCC）。

- READ UNCOMMITED(为提交读)
- READ COMMITED(提交读)
- REPEATABLE READ(可重复读)
- SERIALIZABLE(可串行化)

##### 3.2 事务并发引发的问题

- 更新丢失：当两个或多个事务选择同一行，然后基于最初选定的值更新该行时，由于每个事务都不知道其他事务的存在，就会发生丢失更新问题。最后的更新覆盖了由其他事务所做的更新。
- 脏读：一个事务对一条数据进行修改，提交前，另一个事务也来对这条数据进行操作，而这条数据处于不一致状态。如果不加控制，第二事务就读取了这些“脏”数据。
- 不可重复读：一个事务在读取某些数据后的某个时间，再次读取之前读过的数据，发现其读出的数据已经发生了改变或者已经被删除了。
- 幻读：一个事务按相同的查询条件重新读取以前检索过的数据，却发现其他事务插入了满足其查询条件的新数据。
- 死锁：两个或者多个事务在同一资源上相互占用，并请求锁定对方占用的资源，从而导致恶性循环。

##### 3.3 事务日志

##### 3.4 MySql中的事务

##### 3.5 MySql的其他一些事情

- MySql中默认数据库的作用
- MySql大小写区分
- 一些MySql数据库引擎
- 表引擎的转换

#### 4. 常用Sql

- 数据定义语言（DDL）

  create database database_name;

  use database_name;

  show tables;

  drop database database_name;

  create table table_name(col_name1 type, col_name2 type);

  desc table_name;

  show create table table_name \G;

  drop table table_name;

  alter table table_name modify col_name1 type;

  alter table table_name add column col_name3 type;

  alter table table_name drop column col_name3;

  alter table table_name change col_name2 col_name3 type;

  > change和modify都可以修改表的定义，不同的是change后面需要两个列名，不方便，但change的优点是可以修改列名称，modify不能。

  alter table table_name add col_name2 type after col_name1;

  alter table table_name add col_name0 type first;

  > AFTER、FIRST是MySql数据库在标准sql上的扩展，其他数据库不一定适用。

  alter table table_name rename table_new_name;

- 数据操作语言（DML）

  insert into amp values(0,1,2,3);

  > 含可空字段、非空但有默认的字段、自增字段，可以不用在insert列表里出现。
  >
  > 可以批量插入，只需要用括号和逗号隔开。

  update emp set sal = 4000 where ename = 'Lisa'；

  update emp a, dept b set a.sal=a.sal*b.deptno,b.deptname=a.ename where a.deptno=b.deptno;

  > 多表更新多用在根据一个表的字段来动态地更新另一个表的字段。

  delete from emp where ename = 'dony';

  delete a from emp as a where a.id = 1;

  delete a,b from emp a,dept b where a.deptno=b.deptno and a.deptno=3;

  > 不加where条件会把表的所有记录删除

  select * from emp;

  select distinct depths from emp;

  select * from emp as a where not exists(select 1 from emp as b where b.name = a.name and b.id>a.id);

  > 查询某列不重复值（投影）和查询某列不重复的所有列的值，重复的取第一条。

  select * from emp where deptno=1 and sal>3000;

  select * from emp order by sal;

  select * from emp order by depths,sal desc;

  > 如果排序字段的值相同，则值相同的字段按照第二个排序字段进行排序，依次类推。如果只有一个排序字段，则字段相同的记录会无序排列。
  >
  > 默认是由低到高，如果由高到低在最后几啊desc。

  select * from emp order by sal limit 3;

  select * from emp order by sal limit 1,3;

  > 默认起始的记录是0，第一个参数可以省略。

  select count(1) from emp;

  select deptno,count(1) from emp group by deptno;

  select deptno,count(1) from emp group by deptno with rollup;

  select deptno,count(1) from emp group by deptno having count(1)>1;

  > 1、统计公司总人数
  >
  > 2、统计各部门总人数
  >
  > 3、统计各部门总人数和公司总人数
  >
  > 4、统计部门总人数大于1的部门和部门总人数

  select sum(sal),max(sal),min(sal) from emp;

  表连接：

  - 内连接

    select ename,deptname from emp,dept where emp.deptno=dept.deptno;

  - 外连接

    - 左连接：包含所有左边表中的记录甚至是右边表中没有和他匹配的记录

      select ename,deptname from emp left join dept on emp.deptno=dept.deptno;

    - 右连接：包含所有右边表中的记录甚至是左边表中没有和他匹配的记录

      select ename,deptname from dept left join emp on emp.deptno=dept.deptno;

    > 上面两个查询语句结果一样，因为换了外连接方式也换了表的顺序。查询出来的结果是即使有的用户名不存在合法的部门，也在结果里。

  子查询：

  select * from emp where deptno in (select deptno from dept);

  select emp.* from emp,dept where emp.deptno=dept.deptno;

  > 如果子查询的记录数唯一，还可以用=代替in。
  >
  > 某些情况下表连接可以代替子查询，很多情况下表连接用于优化子查询。

  记录联合：

  > UNION是将UNION ALL的结果进行DISTINCT。

  select deptno from emp union all select deptno from dept;

  其他sql运算：

  全外联合（full outer join）:  并集；内联合（inner join）：交集

  差集的两种实现：

  select table1.id from table1 where not exists(select 1 from table2 where table1.id = table2.id);

  select table1.id from table1 left join table2 on table1.id=table2.id where table2.id is null;

- 数据库管理语言（DCL）

  grant select,insert on test.* to 'yzf'@'localhost' identified by '123';

  > 创建一个用户yzf，对test数据库具有查、增的权限

  revoke insert on test.* from 'yzf'@'localhost';