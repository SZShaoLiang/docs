+ EnableDiscoveryClient

+ 实现类选择与Spring Bean注入

+ EnableDiscoveryClientImportSelector

  使用

+ AutoServiceRegistrationConfiguration

+ EurekaDiscoveryClient

+ EurekaClientConfigBean

+ InetUtils

  获取所有网卡，依次进行遍历，取**ip地址合理、索引值最小且不在忽略列表**的网卡的ip地址作为结果。如果仍然没有找到合适的IP, 那么就将`InetAddress.getLocalHost()`做为最后的fallback方案。

EurekaClientAutoConfiguration中的eurekaInstanceConfigBean方法会构造并返回一个EurekaInstanceConfigBean，EurekaInstanceConfigBean的构造方法如下：

```
public EurekaInstanceConfigBean(InetUtils inetUtils) {
        this.inetUtils = inetUtils;
        this.hostInfo = this.inetUtils.findFirstNonLoopbackHostInfo();
        this.ipAddress = this.hostInfo.getIpAddress();
        this.hostname = this.hostInfo.getHostname();
    }123456
```

在这个时间点，application.yml中的配置已经加载，spring boot的配置文件在容器创建之前就全加载完了。

+ EnvironmentPostProcessor
+ Spring的监听器,Spring根据应用启动的过程,提供了四种事件供我们使用:
  - ApplicationStartedEvent ：spring boot启动开始时执行的事件
  - ApplicationEnvironmentPreparedEvent：spring boot 对应Enviroment已经准备完毕，但此时上下文context还没有创建。
  - ApplicationPreparedEvent：spring boot上下文context创建完成，但此时spring中的bean是没有完全加载完成的。
  - ApplicationFailedEvent：spring boot启动异常时执行事件

