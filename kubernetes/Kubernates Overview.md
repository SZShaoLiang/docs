# Kubernates

### 一、安装

### 二、资源调度

+ node
+ pod

### 三、运行时

1. Deployment 或 ReplicaSet
2. StatefulSets（有状态服务）
   + 使用场景（常用在不支持云原生的高可用集群里）
     + 每个Set需要挂载单独的volume
     + 每个Set需要指定network的host，而不能使用service来做服务发现

### 四、网络

1. Ingress（外部访问的暴露与负载均衡）
   + Ingress with Zuul
   + Ingress with Nginx
   + Ingress with HAproxy

### 五、储存

