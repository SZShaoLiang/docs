---
title: Linux命令备忘录
date: 2017-02-07 00:06:29
tags: [linux,指令]
---

### Linux命令：
#### 指令查询：http://www.runoob.com/linux/linux-command-manual.html
#### 常用指令

    ls　　  显示文件或目录
      -l     列出文件详细信息l(list)
      -a     列出当前目录下所有文件及目录，包括隐藏的a(all)
    mkdir   创建目录
      -p      创建目录，若无父目录，则创建p(parent)
    cd      切换目录
    touch   创建空文件
    echo    创建带有内容的文件。
    cat     查看文件内容
    cp      拷贝
    mv      移动或重命名
    rm      删除文件
      -r      递归删除，可删除子目录及文件
      -f      强制删除
    find    在文件系统中搜索某文件
    wc      统计文本中行数、字数、字符数
    grep    在文本文件中查找某个字符串
    rmdir   删除空目录
    tree    树形结构显示目录，需要安装tree包
    pwd     显示当前目录
    ln      创建链接文件
    more、less    分页显示文本文件内容
    head、tail    显示文件头、尾内容

    ctrl+alt+F1  命令行全屏模式

<!-- more -->
#### 系统管理命令

    stat      显示指定文件的详细信息，比ls更详细
    who       显示在线登陆用户
    whoami    显示当前操作用户
    hostname  显示主机名
    uname     显示系统信息
    top       动态显示当前耗费资源最多进程信息
    ps        显示瞬间进程状态 ps -aux
    du        查看目录大小 du -h /home带有单位显示目录信息
    df        查看磁盘大小 df -h 带有单位显示磁盘信息
    ifconfig  查看网络情况
    ping      测试网络连通
    netstat   显示网络状态信息
    man       命令不会用了，找男人  如：man ls
    clear     清屏
    alias     对命令重命名 如：alias showmeit="ps -aux" ，另外解除使用unaliax showmeit
    kill      杀死进程，可以先用ps 或 top命令查看进程的id，然后再用kill命令杀死进程。

#### 打包压缩相关命令

    gzip：
    bzip2：
    tar:      打包压缩
      -c        归档文件
      -x        压缩文件
      -z        gzip压缩文件
      -j        bzip2压缩文件
      -v        显示压缩或解压缩过程 v(view)
      -f        使用档名

    e.g.:
      tar -cvf /home/abc.tar /home/abc    只打包，不压缩
      tar -zcvf /home/abc.tar.gz /home/abc   打包，并用gzip压缩
      tar -jcvf /home/abc.tar.bz2 /home/abc   打包，并用bzip2压缩
      当然，如果想解压缩，就直接替换上面的命令  tar -cvf  / tar -zcvf  / tar -jcvf 中的“c” 换成“x” 就可以了。

#### 关机/重启机器

    shutdown
      -r        关机重启
      -h        关机不重启
      now       立刻关机
    halt      关机
    reboot    重启

#### Linux管道
>将一个命令的标准输出作为另一个命令的标准输入。也就是把几个命令组合起来使用，后一个命令除以前一个命令的结果。

例：grep -r "close" /home/* | more       在home目录下所有文件中查找，包括close的文件，并分页输出。

#### Linux软件包管理

    dpkg (Debian Package)管理工具，软件包名以.deb后缀。这种方法适合系统不能联网的情况下。
    比如安装tree命令的安装包，先将tree.deb传到Linux系统中。再使用如下命令安装。
    sudo dpkg -i tree_1.5.3-1_i386.deb         安装软件
    sudo dpkg -r tree                          卸载软件

 注：将tree.deb传到Linux系统中，有多种方式。VMwareTool，使用挂载方式；使用winSCP工具等；

    APT（Advanced Packaging Tool）高级软件工具。这种方法适合系统能够连接互联网的情况。
    依然以tree为例
    sudo apt-get install tree                  安装tree
    sudo apt-get remove tree                   卸载tree
    sudo apt-get update                        更新软件

    sudo apt-get upgrade           将.rpm文件转为.deb文件

    .rpm为RedHat使用的软件格式。在Ubuntu下不能直接使用，所以需要转换一下。
    sudo alien abc.rpm

#### vim使用

>vim三种模式：命令模式、插入模式、编辑模式。使用ESC或i或：来切换模式。

      命令模式下：
        :q        退出
        :q!       强制退出
        :wq       保存并退出
        :set number     显示行号
        :set nonumber   隐藏行号
        /apache   在文档中查找apache 按n跳到下一个，shift+n上一个
        yyp                   复制光标所在行，并粘贴
        h(左移一个字符←)、j(下一行↓)、k(上一行↑)、l(右移一个字符→)

#### 用户及用户组管理

    /etc/passwd    存储用户账号
    /etc/group     存储组账号
    /etc/shadow    存储用户账号的密码
    /etc/gshadow   存储用户组账号的密码
    useradd 用户名
    userdel 用户名
    adduser 用户名
    groupadd 组名
    groupdel 组名
    passwd root    给root设置密码
    su root
    su - root

    /etc/profile   系统环境变量
    bash_profile   用户环境变量
    .bashrc        用户环境变量

    su user        切换用户，加载配置文件.bashrc
    su - user      切换用户，加载配置文件/etc/profile ，加载bash_profile

    更改文件的用户及用户组
    sudo chown [-R] owner[:group] {File|Directory}
    例如：还以jdk-7u21-linux-i586.tar.gz为例。属于用户hadoop，组hadoop
    要想切换此文件所属的用户及组。可以使用命令。
    sudo chown root:root jdk-7u21-linux-i586.tar.gz

#### 文件权限管理
    三种基本权限
    R     读     数值表示为4
    W     写     数值表示为2
    X     可执行  数值表示为1

    jdk-7u21-linux-i586.tar.gz文件的权限为-rw-rw-r--。
    -rw-rw-r--一共十个字符，分成四段。
    第一个字符“-”表示普通文件；这个位置还可能会出现“l”链接；“d”表示目录
    第二三四个字符“rw-”表示当前所属用户的权限。   所以用数值表示为4+2=6
    第五六七个字符“rw-”表示当前所属组的权限。      所以用数值表示为4+2=6
    第八九十个字符“r--”表示其他用户权限。              所以用数值表示为2
    所以操作此文件的权限用数值表示为662

    更改权限

    sudo chmod [u所属用户  g所属组  o其他用户  a所有用户]  [+增加权限  -减少权限]  [r  w  x]   目录名

    例如：有一个文件filename，权限为“-rw-r----x” ,将权限值改为"-rwxrw-r-x"，用数值表示为765
    sudo chmod u+x g+w o+r  filename
    上面的例子可以用数值表示
    sudo chmod 765 filename

### Linux目录：
#### /bin：
bin是Binary的缩写, 这个目录存放着最经常使用的命令。
#### /boot：
这里存放的是启动Linux时使用的一些核心文件，包括一些连接文件以及镜像文件。
#### /dev ：
dev是Device(设备)的缩写, 该目录下存放的是Linux的外部设备，在Linux中访问设备的方式和访问文件的方式是相同的。
#### /etc：
这个目录用来存放所有的系统管理所需要的配置文件和子目录。
#### /home：
用户的主目录，在Linux中，每个用户都有一个自己的目录，一般该目录名是以用户的账号命名的。
#### /lib：
这个目录里存放着系统最基本的动态连接共享库，其作用类似于Windows里的DLL文件。几乎所有的应用程序都需要用到这些共享库。
#### /lost+found：
这个目录一般情况下是空的，当系统非法关机后，这里就存放了一些文件。
#### /media l
inux系统会自动识别一些设备，例如U盘、光驱等等，当识别后，linux会把识别的设备挂载到这个目录下。
#### /mnt：
系统提供该目录是为了让用户临时挂载别的文件系统的，我们可以将光驱挂载在/mnt/上，然后进入该目录就可以查看光驱里的内容了。
#### /opt：
这是给主机额外安装软件所摆放的目录。比如你安装一个ORACLE数据库则就可以放到这个目录下。默认是空的。
#### /proc：
这个目录是一个虚拟的目录，它是系统内存的映射，我们可以通过直接访问这个目录来获取系统信息。
这个目录的内容不在硬盘上而是在内存里，我们也可以直接修改里面的某些文件，比如可以通过下面的命令来屏蔽主机的ping命令，使别人无法ping你的机器：
echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_all
#### /root：
该目录为系统管理员，也称作超级权限者的用户主目录。
#### /sbin：
s就是Super User的意思，这里存放的是系统管理员使用的系统管理程序。
#### /selinux：
这个目录是Redhat/CentOS所特有的目录，Selinux是一个安全机制，类似于windows的防火墙，但是这套机制比较复杂，这个目录就是存放selinux相关的文件的。
#### /srv：
该目录存放一些服务启动之后需要提取的数据。
#### /sys：
这是linux2.6内核的一个很大的变化。该目录下安装了2.6内核中新出现的一个文件系统 sysfs 。
sysfs文件系统集成了下面3种文件系统的信息：针对进程信息的proc文件系统、针对设备的devfs文件系统以及针对伪终端的devpts文件系统。
该文件系统是内核设备树的一个直观反映。
当一个内核对象被创建的时候，对应的文件和目录也在内核对象子系统中被创建。
#### /tmp：
这个目录是用来存放一些临时文件的。
#### /usr：
这是一个非常重要的目录，用户的很多应用程序和文件都放在这个目录下，类似与windows下的program files目录。
#### /usr/bin：
系统用户使用的应用程序。
#### /usr/sbin：
超级用户使用的比较高级的管理程序和系统守护程序。
#### /usr/src：
内核源代码默认的放置目录。
#### /var：
这个目录中存放着在不断扩充着的东西，我们习惯将那些经常被修改的目录放在这个目录下。包括各种日志文件。
在linux系统中，有几个目录是比较重要的，平时需要注意不要误删除或者随意更改内部文件。
#### /etc：
上边也提到了，这个是系统中的配置文件，如果你更改了该目录下的某个文件可能会导致系统不能启动。
#### /bin, /sbin, /usr/bin, /usr/sbin:
这是系统预设的执行文件的放置目录，比如 ls 就是在/bin/ls 目录下的。值得提出的是，/bin, /usr/bin 是给系统用户使用的指令（除root外的通用户），而/sbin, /usr/sbin 则是给root使用的指令。
#### /var：
这是一个非常重要的目录，系统上跑了很多程序，那么每个程序都会有相应的日志产生，而这些日志就被记录到这个目录下，具体在/var/log 目录下，另外mail的预设放置也是在这里。


参考：http://www.weixuehao.com/archives/25
