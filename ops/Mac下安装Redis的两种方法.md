---
title: Mac下安装Redis的两种方法
date: 2017-02-10 18:13:34
tags: [redis,mac]
---
 >本文主要介绍了redis的安装方法，以及redis的配置、Python客户端模块的安装。

### 第一种方法：
>OS X系统上面已经安装了Xcode，使用Xcode编译redis二进制文件

#### 下载源码并build redis

    $ curl -O http://download.redis.io/releases/redis-3.2.7.tar.gz
    $ tar -zxvf redis-3.2.7.tar.gz
    $ cd redis-3.2.7
    $ make test
    $ make

注：当前时间Redis稳定版本为3.2.7。
<!-- more -->
#### 搭建redis服务器

    $ mkdir -p /usr/local/redis/{conf,data,bin,log}
    $ mv src/redis-server src/redis-cli src/redis-sentinel src/redis-check-dump src/redis-benchmark src/redis-check-aof /usr/local/redis/bin
    $ cp redis.conf /usr/local/redis/conf/6379.conf

#### 安装redis的Python客户端

    $ mkdir ~/Workspace/python/redis_demo
    $ cd ~/Workspace/python/redis_demo
    $ pip install redis
    $ touch demo.py

注：pip安装方法:http://pip-cn.readthedocs.io/en/latest/installing.html。

#### redis服务器的启动

    $ cd /usr/local/redis/bin
    $ ./redis-server ../conf/6379.conf

### 第二种方法
>使用rudix(http://rudix.org/) 安装redis

#### 安装rudix
>rudix is a collection of pre-built Unix-like software delivered as packages for Macintoshes.
>rudix可以直接以预编译二进制的形式安装各式各样的软件，有哪些软件可以查看rudix在github上的项目：https://github.com/rudix-mac/rudix

Quick Start
There is two ways to have the Rudix Package manager installed. You can download the proper package and install it from packages > rudix or you can bootstrap by using the command line.

Just open the Terminal.app and type:

     $ curl -O https://raw.githubusercontent.com/rudix-mac/rpm/2016.12.13/rudix.py
     $ sudo python rudix.py install rudix

or even compressed in one-line:

    curl -s https://raw.githubusercontent.com/rudix-mac/rpm/2016.12.13/rudix.py | sudo python - install rudix


#### 安装redis

    $ sudo rudix install redis

注：这个时间redis官方最新稳定版为3.2.7，但rudix默认的是3.0.3，rudix默认版本可以在github上看到。

#### 安装redis的Python客户端

    $ sudo rudix install pip
    $ sudo pip install redis

### 修改redis启动配置

```
$ vi /usr/local/redis/conf/6379.conf

#更改 6379.conf 中的内容如下
################################ GENERAL  #####################################
# 设置为后台运行
daemonize yes

# 设置pid文件位置
pidfile /usr/local/redis/redis.pid

# 配置默认端口号
port 6379

# TCP listen() backlog
tcp-backlog 511

# 连接超时时间设置为120秒
timeout 120

# TCP keepalive.
tcp-keepalive 0

# Specify the server verbosity level.
# This can be one of:
# debug (a lot of information, useful for development/testing)
# verbose (many rarely useful info, but not a mess like the debug level)
# notice (moderately verbose, what you want in production probably)
# warning (only very important / critical messages are logged)
# 设置日志级别
loglevel debug

# 设置日志文件位置
logfile "/usr/local/redis/log/6379.log"

# 设置数据库个数为 16个
databases 16

################################ SNAPSHOTTING  ################################
# 快照的存储方式: 时间 更新次数
save 900 1
save 300 10
save 60 10000

stop-writes-on-bgsave-error yes

rdbcompression yes

rdbchecksum yes

# 数据文件名
dbfilename dump.rdb

# 数据文件所在目录
dir /usr/local/redis/data/6379

################################# REPLICATION #################################
slave-serve-stale-data yes
slave-read-only yes
repl-diskless-sync no
repl-diskless-sync-delay 5
repl-disable-tcp-nodelay no
slave-priority 100
################################## SECURITY ###################################
appendonly no

appendfilename "appendonly.aof"

# appendfsync always
appendfsync everysec
# appendfsync no

no-appendfsync-on-rewrite no

auto-aof-rewrite-percentage 100

auto-aof-rewrite-min-size 64mb

aof-load-truncated yes

################################ LUA SCRIPTING  ###############################
lua-time-limit 5000

################################## SLOW LOG ###################################

slowlog-log-slower-than 10000

slowlog-max-len 128

################################ LATENCY MONITOR ##############################

latency-monitor-threshold 0

############################# EVENT NOTIFICATION ##############################

notify-keyspace-events ""

############################### ADVANCED CONFIG ###############################
hash-max-ziplist-entries 512
hash-max-ziplist-value 64

list-max-ziplist-entries 512
list-max-ziplist-value 64

set-max-intset-entries 512

zset-max-ziplist-entries 128
zset-max-ziplist-value 64

hll-sparse-max-bytes 3000

activerehashing yes

client-output-buffer-limit normal 0 0 0
client-output-buffer-limit slave 256mb 64mb 60
client-output-buffer-limit pubsub 32mb 8mb 60

hz 10

aof-rewrite-incremental-fsync yes
```
