### Spring Boot加载属性的位置

+ 命令行参数
+ 从java:comp/env获取到的JNDI属性
+ System.getProperties()属性
+ 操作系统的环境变量
+ 文件系统上的外部属性文件:(config/)?application.(iml.proper ties)
+ 归档(config/)?application.(iml.properties)文件中的属性文件
+ 配置类上的@PropertySource注解
+ SpringApplication.getDefaultProperties()提供的默认属性