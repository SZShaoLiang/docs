# Docker

### 常用命令

### 容器网络

##### 默认：

1. none
2. host
3. bridge
   + 容器间通信
     + bind
     + link
     + 全部暴漏，使用外部网络访问
   + 暴漏端口
4. ovlary

##### 自建：

##### compose里的网络：

### 存储

### Dockerfile

+ CMD
+ ENTRYPOINT

### Compose 2.x

1. 问题
   + compose中相同image，但command不同，这时需要使用extend，但在compose3.x中没有这个属性
   + 覆写应用配置文件中的配置，比如数据库连接与用户名密码等

### SHELL

1. shell脚本获取Dockerfile或者docker-compose中的环境变量

   + 从Dockerfile中的ENV定义中获取

     > 一般放一些不变的环境变量

     ```
     Environment variables are notated in the Dockerfile either with $variable_name or ${variable_name}. They are treated equivalently and the brace syntax is typically used to address issues with variable names with no whitespace, like ${foo}_bar.

     The ${variable_name} syntax also supports a few of the standard bash modifiers as specified below:

     ${variable:-word} indicates that if variable is set then the result will be that value. If variable is not set then word will be the result.
     ${variable:+word} indicates that if variable is set then word will be the result, otherwise the result is the empty string.
     In all cases, word can be any string, including additional environment variables.

     Escaping is possible by adding a \ before the variable: \$foo or \${foo}, for example, will translate to $foo and ${foo} literals respectively.
     ```

   + 从CMD命令数组中获取

   + 从docker-compose中的environment中获取

     > 放一些需要用户自定义的环境变量

2. docker shell 的权限

3. 使用docker run command覆盖CMD

   ```
   docker run [OPTIONS] IMAGE[:TAG] [COMMAND] [ARG...]
   ```

   This command is optional because the person who created the IMAGE may have already provided a default COMMAND using the Dockerfile CMD. As the operator (the person running a container from the image), you can override that CMD just by specifying a new COMMAND.

   If the image also specifies an ENTRYPOINT then the CMD or COMMAND get appended as arguments to the ENTRYPOINT.

   So to do what you want you need *only* specify a cmd, and override using `/bin/bash`. Not quite "empty", but it get the job done 99%.

