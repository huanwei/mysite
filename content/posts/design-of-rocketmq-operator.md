---
title: "Design of Rocketmq Operator"
date: 2018-09-10T23:44:13+08:00
draft: false
description: "最近业余时间写了个 RocketMQ Operator，简单说说设计思路。"
---

## 设计目标

Kubernetes PaaS 环境下，可伸缩(auto-scale)、可自愈（self-healing）的 RocketMQ Clusters 运维。

## 背景与踩坑

RocketMQ 的集群有它自己的集群管理模式，简单来说，关键有以下几点：

1）RocketMQ Namesrv 是一个无状态的集群；

2）RocketMQ Broker 是一个有状态的集群，根据主备模式及 Replication Mode，总的来说可分为三种： all-master 模式、sync/async master-slave 模式。

3）Broker 依赖于 Namesrv，Broker启动时需要知道 Namesrv 的地址列表；

4) 其中很容易想到的一点是：既然 Namesrv 是一个无状态的服务，那么在同一个集群内可否将 Namesrv 服务地址（即 service name/namespace）配置给 Broker ？答案是不行，至少目前 RocketMQ 不支持这种方式，经实验，当 Namesrv 仅有一个replica时，可以这样配置，但是当其有多个replica时，这样配置后使用mqadmin得到的clusterList信息并不保证一致。

## 设计思路

经过上述背景分析、并设计了几个yaml文件进行踩坑之后，简单设计如下：

1）首先给节点打label，意图是集群各组件节点可按 nodeSelector 启动，便于开发测试，另外一个意图是私有化场景下，后续的存储或许可往Local Volume方式迁移；

2）集群首先部署Namesrv集群，一个deployment配置多个replica即可，暂且以NodePort方式为后续的Broker集群服务；

3) 设计BrokerCluster CRD，托管多组Broker StatefulSet及其headless service，通过一个Cluster Controller，使得headless service以及StatefulSet创建时，通过环境变量的方式，给预先埋在Broker镜像中的脚本程序传值，以此为各Broker容器动态生成
上述各集群模式中最为关键broker.conf配置文件，即可；

4）存储暂且先用hostPath，各实例的路径以Statefulset index区分。

## 具体实现

具体实现见代码 [rocketmq-operator](https://github.com/huanwei/rocketmq-operator)

## 可优化点

假如考虑Namesrv和Broker都处于同一个Kubernetes集群内，那么可以自动创建Namesrv deployment，然后Broker启动前获取Namesrv endpoints列表，并list-watch该Namesrv endpoints列表；

只不过当Namesrv endpoints列表的list-watch信息发生变动时，此时各Broker实例就需要靠rolling-update逐个重启以刷新存放于Broker内存的配置，这是由于RocketMQ集群方式导致，并不很友好。




