---
title: "kubeadm源码分析"
date: 2016-12-22T19:44:35+08:00
draft: false
description: "这两天分析了一下Kubernetes中kubeadm模块的源码。"
---

这两天分析了一下Kubernetes中kubeadm模块的源码。

### 说明
以下源码分析基于 kubernetes v1.5.1 版本（目前的最新版本，released 8 days ago），与其他版本不一定一致。

### 阅读对象
熟悉kubernetes基本原理、对源码有一定追求的技术人。

## 一、程序主入口分析
看代码目录结构，可以看到1.5版本以上的kubernetes源码已经包含了kubeadm；
kubeadm源码位于其中cmd包下的kubeadm目录；
其中的/cmd/kuberadm/kubeadm.go是程序的主入口；
程序主要片段及注释：

```
package main
import ... （略）

func main() {
	if err := app.Run(); err != nil { //主程序入口
		fmt.Printf(util.AlphaWarningOnExit)
		os.Exit(1)
	}
	os.Exit(0)
}
```

kubeadm.go只有一个main()函数，它执行app.Run()，app包里的Run()则定义在另一个/kubeadm/app/kubeadm.go里，它调用cmd包下的NewKubeadmCommand() 来创建新的Kubeadm命令，并调用cmd.Execute() 使之生效；

程序主要片段及注释：

```
package app
import ... （略）

func Run() error {
	logs.InitLogs()
	defer logs.FlushLogs()

	// We do not want these flags to show up in --help
	pflag.CommandLine.MarkHidden("google-json-key")
	pflag.CommandLine.MarkHidden("log-flush-frequency")

	//主要工作：
	//调用cmd包下的NewKubeadmCommand()来创建新的Kubeadm命令
	cmd := cmd.NewKubeadmCommand(cmdutil.NewFactory(nil), os.Stdin, os.Stdout, os.Stderr)
	//并调用cmd.Execute() 使之生效
	return cmd.Execute()
}
```

NewKubeadmCommand() 调用AddCommand(NewCmdInit())、AddCommand(NewCmdJoin())以及AddCommand(NewCmdReset())、AddCommand(NewCmdToken())、AddCommand(NewCmdVersion())分别创建了kubeadm init、kubeadm join、kubeadm reset、kubeadm token、kubeadm version这5条命令。

```
package cmd
import ... （略）

func NewKubeadmCommand(f cmdutil.Factory, in io.Reader, out, err io.Writer) *cobra.Command {
	cmds := &cobra.Command{
		Use:   "kubeadm",
		... （略）

	cmds.ResetFlags()
	cmds.SetGlobalNormalizationFunc(flag.WarnWordSepNormalizeFunc)

	//分别创建以下5个命令
	/*
	kubeadm init主要完成了通信令牌（用于双向认证）的创建、证书及密钥的生成、master节点的注册以及各个组件的启动。
	*/
	cmds.AddCommand(NewCmdInit(out))
	/*
	kubeadm join根据令牌获取集群信息，并生成节点kubelet配置文件。下一次节点上的kubelet就可以按已有的配置进行重启，开始生效。
	*/
	cmds.AddCommand(NewCmdJoin(out))
	/*
	kubeadm reset主要是回退当前节点在之前执行kubeadm init或者kubeadm join的执行结果。
	*/
	cmds.AddCommand(NewCmdReset(out))
	/*
	kubeadm token主要是可以事先生成一个token供init或join时使用。
	*/
	cmds.AddCommand(NewCmdToken(out))
	/*
	kubeadm version主要是获取kubeadm版本信息。
	*/
	cmds.AddCommand(NewCmdVersion(out))

	return cmds
}
```

下面按顺序对kubeadm init、kubeadm join、kubeadm reset、kubeadm token、kubeadm version的源码进行简单分析。

## 二、kubeadm init分析
NewCmdInit()的实现在app/cmd/init.go里，它创建了一个cobra.Command类型的命令对象，并指定了该命令的相关参数；

```
package cmd
import ... （略）

// NewCmdInit returns "kubeadm init" command.
func NewCmdInit(out io.Writer) *cobra.Command {
	versioned := &kubeadmapiext.MasterConfiguration{}
	api.Scheme.Default(versioned)
	cfg := kubeadmapi.MasterConfiguration{}
	api.Scheme.Convert(versioned, &cfg, nil)

	var cfgPath string
	var skipPreFlight bool
	//创建一个cobra.Command类型的命令对象，并指定该命令的相关参数
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Run this in order to set up the Kubernetes master",
		//实际运行的是这里
		Run: func(cmd *cobra.Command, args []string) {
			//执行init一些准备工作，如获取本机IP等初始化配置
			i, err := NewInit(cfgPath, &cfg, skipPreFlight)
			kubeadmutil.CheckErr(err)
			//主要工作在下面这个i.Run()方法
			kubeadmutil.CheckErr(i.Run(out))
		},
	}

... （略）
```

NewCmdInit()方法首先调用NewInit()方法执行init的一些准备工作，如获取本机IP等初始化配置；

```
func NewInit(cfgPath string, cfg *kubeadmapi.MasterConfiguration, skipPreFlight bool) (*Init, error) {
	... （略）
	// Auto-detect the IP
	if len(cfg.API.AdvertiseAddresses) == 0 {
		// TODO(phase1+) perhaps we could actually grab eth0 and eth1
		//目前是去 /proc/net/route 里获取本机IP
		ip, err := netutil.ChooseHostInterface()
		if err != nil {
			return nil, err
		}
		cfg.API.AdvertiseAddresses = []string{ip.String()}
	}

	... （略）
	// TODO(phase1+) create a custom flag
	// 判断是否在云主机上进行部署，后续的操作还没有实现。。
	if cfg.CloudProvider != "" {
		if cloudprovider.IsCloudProvider(cfg.CloudProvider) {
			fmt.Printf("cloud provider %q initialized for the control plane. Remember to set the same cloud provider flag on the kubelet.\n", cfg.CloudProvider)
		} else {
			return nil, fmt.Errorf("cloud provider %q is not supported, you can use any of %v, or leave it unset.\n", cfg.CloudProvider, cloudprovider.CloudProviders())
		}
	}
	return &Init{cfg: cfg}, nil
}
```

NewCmdInit()方法然后调用NewInit()方法返回结果执行i.Run()方法，主要工作就在这里：

```
// Run executes master node provisioning, including certificates, needed static pod manifests, etc.
func (i *Init) Run(out io.Writer) error {
	/*
	主要工作：
	创建令牌文件(token)。创建过程为：
	1.调用generateTokenIfNeeded() 检查是否需要创建令牌；
	  目前相应操作还未实现，所以会生成新的令牌, 并在屏幕输出“<master/tokens> generated token”信息;
	2.调用os.MkdirAll()创建用来存放令牌文件的目录；MkdirAll()可以看作是Go语言对mkdir -p的实现；
	3.序列化生成的令牌;
	4.调用cmdutil.DumpReaderToFile()将其写入文件。
	*/
	if err := kubemaster.CreateTokenAuthFile(&i.cfg.Secrets); err != nil {
		return err
	}

	/*
	主要工作：
	创建静态Pod资源描述文件。
	这些Pod包括Kubernetes的基础组件：kubeAPIServer、kubeControllerManager、kubeScheduler以及etcd。
	这些资源描述文件都是json格式，指定了相关的镜像及运行参数。
	*/
	if err := kubemaster.WriteStaticPodManifests(i.cfg); err != nil {
		return err
	}

	/*
	主要工作：
	创建公钥基础设施：
	首先创建服务端自签名CA证书，以及供token签名的key；
	最后将它们写入文件 /etc/kubernetes/pki；
	并输出“<master/pki> created keys and certificates in /etc/kubernetes/pki”的信息。
	*/
	caKey, caCert, err := kubemaster.CreatePKIAssets(i.cfg)
	if err != nil {
		return err
	}

	/*
	主要工作：
	创建客户端配置，指定访问的地址和端口，以及确定证书；
	并调用kubeadmutil.WriteKubeconfigIfNotExists()方法,
	将两个配置文件分别写入/etc/kubernetes/kubelet.conf 和 /etc/kubernetes/admin.conf，
	并输出<util/config> created ...相关信息。
	*/
	kubeconfigs, err := kubemaster.CreateCertsAndConfigForClients(i.cfg.API, []string{"kubelet", "admin"}, caKey, caCert)
	if err != nil {
		return err
	}

	// kubeadm is responsible for writing the following kubeconfig file, which
	// kubelet should be waiting for. Help user avoid foot-shooting by refusing to
	// write a file that has already been written (the kubelet will be up and
	// running in that case - they'd need to stop the kubelet, remove the file, and
	// start it again in that case).
	// TODO(phase1+) this is no longer the right place to guard agains foo-shooting,
	// we need to decide how to handle existing files (it may be handy to support
	// importing existing files, may be we could even make our command idempotant,
	// or at least allow for external PKI and stuff)
	for name, kubeconfig := range kubeconfigs {
		//将两个配置文件分别写入 /etc/kubernetes/kubelet.conf 和 /etc/kubernetes/admin.conf
		if err := kubeadmutil.WriteKubeconfigIfNotExists(name, kubeconfig); err != nil {
			return err
		}
	}


	/*
	主要工作：
	1.根据前面创建的admin.conf配置创建客户端配置，输出“<master/apiclient> created API client configuration”；
	2.根据配置创建API客户端，并等待“<master/apiclient> created API client, waiting for the control plane to become ready”；
	3.调用wait.PollInfinite()，传入条件函数对各个组件的健康状态进行无限探测，每隔apiCallRetryInterval（默认500毫秒）一次，直到所有的组件都健康，并计算花费的时间。
	  输出“<master/apiclient> all control plane components are healthy after %f seconds”信息。
	4.再次以同样频率调用wait.PollInfinite()，传入条件函数不断检测是否有节点加入，直到至少一个节点注册并就绪。
	  如果有多个节点，会选择第一个进行注册。同时输出“<master/apiclient> first node is ready after %f seconds\n”信息。
	*/
	client, err := kubemaster.CreateClientAndWaitForAPI(kubeconfigs["admin"])
	if err != nil {
		return err
	}

	//确定该节点为master节点，并设置为“不可调度”，即不是工作节点。
	schedulePodsOnMaster := false
	if err := kubemaster.UpdateMasterRoleLabelsAndTaints(client, schedulePodsOnMaster); err != nil {
		return err
	}

	/*
	主要工作：
	1.创建KubeDiscovery实例；
	2.输出“<master/discovery> created essential addon: kube-discovery, waiting for it to become ready”信息；
	3.依然调用wait.PollInfinite()，传入条件函数不停获取KubeDiscovery实例，直到它拥有一个可用实例为止；
	4.计算等待的时间，并输出“<master/discovery> kube-discovery is ready after %f seconds”信息。
	*/
	if err := kubemaster.CreateDiscoveryDeploymentAndSecret(i.cfg, client, caCert); err != nil {
		return err
	}

	/*
	主要工作：
	1.创建KubeProxy的DaemonSet，以及KubeDNS实例。
	2.最后发布DNS的Service，输出“<master/addons> created essential addon: kube-dns”信息。
	*/
	if err := kubemaster.CreateEssentialAddons(i.cfg, client); err != nil {
		return err
	}

	/*
	主要工作：
	所有工作完成后，输出Kubernetes master initialised successfully! You can now join any number of machines by running the following on each node: kubeadm join --token %s %s信息，
	表示master节点配置结束。
	*/
	data := joinArgsData{i.cfg, kubeadmapiext.DefaultAPIBindPort, kubeadmapiext.DefaultDiscoveryBindPort}
	if joinArgs, err := generateJoinArgs(data); err != nil {
		return err
	} else {
		fmt.Fprintf(out, initDoneMsgf, joinArgs) //输出信息
	}
	return nil
}
```

小结：
从以上源码分析可以大致知道，kubeadm init主要完成了通信令牌（用于双向认证）的创建、证书及密钥的生成、master节点的注册以及各个组件的启动。

## 三、kubeadm join分析
NewCmdJoin()的实现在app/cmd/join.go里，与NewCmdInit()类似，它也是创建了一个cobra.Command类型的命令对象，并指定了该命令的相关参数；

```
package cmd
import ... （略）

// NewCmdJoin returns "kubeadm join" command.
func NewCmdJoin(out io.Writer) *cobra.Command {
	versioned := &kubeadmapiext.NodeConfiguration{}
	api.Scheme.Default(versioned)
	cfg := kubeadmapi.NodeConfiguration{}
	api.Scheme.Convert(versioned, &cfg, nil)

	var skipPreFlight bool
	var cfgPath string

	//创建一个cobra.Command类型的命令对象，并指定该命令的相关参数
	cmd := &cobra.Command{
		Use:   "join <master address>",
		Short: "Run this on any machine you wish to join an existing cluster",
		Run: func(cmd *cobra.Command, args []string) {
			j, err := NewJoin(cfgPath, args, &cfg, skipPreFlight)
			kubeadmutil.CheckErr(err)
			//重点是下面这个j.Run()函数
			kubeadmutil.CheckErr(j.Run(out))
		},
	}

... （略）
```

NewCmdJoin()方法首先调用NewJoin()方法执行init的一些准备工作，比如检查是否有命令参数、检查令牌格式是否合法；

```
func NewJoin(cfgPath string, args []string, cfg *kubeadmapi.NodeConfiguration, skipPreFlight bool) (*Join, error) {
	... （略）
	//首先会检查是否有命令参数。
	//在节点上执行的kubeadm join命令是前面kubeadm init生成的结果，包含了令牌及master节点地址作为参数。

	if len(args) == 0 && len(cfg.MasterAddresses) == 0 {
		return nil, fmt.Errorf("must specify master address (see --help)")
	}
	cfg.MasterAddresses = append(cfg.MasterAddresses, args...)
	if len(cfg.MasterAddresses) > 1 {
		return nil, fmt.Errorf("Must not specify more than one master address  (see --help)")
	}

	... （略）
	//检查令牌格式的合法性
	//输出“<util/tokens> validating provided token”
	ok, err := kubeadmutil.UseGivenTokenIfValid(&cfg.Secrets)
	if !ok {
		if err != nil {
			return nil, fmt.Errorf("%v (see --help)\n", err)
		}
		return nil, fmt.Errorf("Must specify --token (see --help)\n")
	}

	return &Join{cfg: cfg}, nil
}
```

NewCmdJoin()方法然后调用NewJoin()方法返回结果执行j.Run()方法，主要工作就在这里：

```
func NewJoin(cfgPath string, args []string, cfg *kubeadmapi.NodeConfiguration, skipPreFlight bool) (*Join, error) {
	if cfgPath != "" {
		b, err := ioutil.ReadFile(cfgPath)
		if err != nil {
			return nil, fmt.Errorf("unable to read config from %q [%v]", cfgPath, err)
		}
		if err := runtime.DecodeInto(api.Codecs.UniversalDecoder(), b, cfg); err != nil {
			return nil, fmt.Errorf("unable to decode config from %q [%v]", cfgPath, err)
		}
	}

	//首先会检查是否有命令参数。
	//在节点上执行的kubeadm join命令是前面kubeadm init生成的结果，包含了令牌及master节点地址作为参数。

	if len(args) == 0 && len(cfg.MasterAddresses) == 0 {
		return nil, fmt.Errorf("must specify master address (see --help)")
	}
	cfg.MasterAddresses = append(cfg.MasterAddresses, args...)
	if len(cfg.MasterAddresses) > 1 {
		return nil, fmt.Errorf("Must not specify more than one master address  (see --help)")
	}

	if !skipPreFlight {
		fmt.Println("Running pre-flight checks")
		err := preflight.RunJoinNodeChecks(cfg)
		if err != nil {
			return nil, &preflight.PreFlightError{Msg: err.Error()}
		}
	} else {
		fmt.Println("Skipping pre-flight checks")
	}

	//检查令牌格式的合法性
	//输出“<util/tokens> validating provided token”
	ok, err := kubeadmutil.UseGivenTokenIfValid(&cfg.Secrets)
	if !ok {
		if err != nil {
			return nil, fmt.Errorf("%v (see --help)\n", err)
		}
		return nil, fmt.Errorf("Must specify --token (see --help)\n")
	}

	return &Join{cfg: cfg}, nil
}

// Run executes worked node provisioning and tries to join an existing cluster.
func (j *Join) Run(out io.Writer) error {

	/*
	主要工作：
	获取集群信息，输出“<node/discovery> created cluster info discovery client, requesting info from”信息；
	向master节点的9898端口发送GET请求，请求的URL为http://MASTER-IP:9898/cluster-info/v1/?token-id=TOKENID；
	返回的结果分解为一个JWS（JsonWebSignature）对象；
	输出“<node/discovery> cluster info object received, verifying signature using given token”后并用该对象的Verify()校验节点令牌，
	校验成功生成集群信息，包含apiServer地址和CA证书，输出“<node/discovery> cluster info signature and contents are valid, will use API endpoints”。
	*/
	clusterInfo, err := kubenode.RetrieveTrustedClusterInfo(j.cfg)
	if err != nil {
		return err
	}

	/*
	主要工作：
	和Master节点建立连接，输出"<node/bootstrap> successfully established connection with endpoint %s\n"信息
	*/
	connectionDetails, err := kubenode.EstablishMasterConnection(j.cfg, clusterInfo)
	if err != nil {
		return err
	}

	/*
	主要工作：
	首先会获取客户端配置信息，并利用主机名作为节点名，生成节点启动配置；
	据此创建客户端API Client，生成key和CSR文件；
	输出“<node/csr> created API client to obtain unique certificate for this node, generating keys and certificate signing request ”，
	并向apiServer请求生成该节点的kubelet的配置信息，
	输出“<node/csr> received signed certificate from the API server, generating kubelet configuration”
	*/
	kubeconfig, err := kubenode.PerformTLSBootstrap(connectionDetails)
	if err != nil {
		return err
	}

	/*
	主要工作：
	将客户端kubelet配置信息写入文件，
	输出“<util/kubeconfig> created /etc/kubernetes/kubelet.conf”。
	*/
	err = kubeadmutil.WriteKubeconfigIfNotExists("kubelet", kubeconfig)
	if err != nil {
		return err
	}

	/*
	主要工作：
	最后输出相应的提示信息：“Node join complete: * Certificate signing request sent to master and response received. * Kubelet informed of new secure connection details.
	Run 'kubectl get nodes' on the master to see this machine join.”
	*/
	fmt.Fprintf(out, joinDoneMsgf)
	return nil
}
```

小结：
kubeadm join根据令牌获取集群信息，并生成节点kubelet配置文件。下一次节点上的kubelet就可以按已有的配置进行重启，开始生效。


## 四、kubeadm reset分析
NewCmdReset()的实现在app/cmd/reset.go里，与NewCmdInit()类似，它也是创建了一个cobra.Command类型的命令对象，并指定了该命令的相关参数；

```
package cmd
import ... （略）

// NewCmdReset returns "kubeadm reset" command.
func NewCmdReset(out io.Writer) *cobra.Command {
	var skipPreFlight bool
	cmd := &cobra.Command{
		Use:   "reset",
		Short: "Run this to revert any changes made to this host by 'kubeadm init' or 'kubeadm join'.",
		Run: func(cmd *cobra.Command, args []string) {
			r, err := NewReset(skipPreFlight)
			kubeadmutil.CheckErr(err)
			//主要工作在下面这个r.Run()方法
			kubeadmutil.CheckErr(r.Run(out))
		},
	}

	cmd.PersistentFlags().BoolVar(
		&skipPreFlight, "skip-preflight-checks", false,
		"skip preflight checks normally run before modifying the system",
	)

	return cmd
}
```

NewReset()方法只做一些简单的前置检查，以上每个命令都有，基本可以忽略不看；
NewCmdReset()方法然后调用NewReset()方法返回结果执行j.Run()方法，主要工作就在这里：

```
// Run reverts any changes made to this host by "kubeadm init" or "kubeadm join".
func (r *Reset) Run(out io.Writer) error {
	//停掉kubelet进程
	serviceToStop := "kubelet"
	initSystem, err := initsystem.GetInitSystem()
	if err != nil {
		fmt.Printf("%v", err)
	} else {
		fmt.Printf("Stopping the %s service...\n", serviceToStop)
		initSystem.ServiceStop(serviceToStop)
	}

	//卸载kubelet生成的文件目录 /var/lib/kubelet
	fmt.Printf("Unmounting directories in /var/lib/kubelet...\n")
	// Don't check for errors here, since umount will return a non-zero exit code if there is no directories to umount
	exec.Command("sh", "-c", "cat /proc/mounts | awk '{print $2}' | grep '/var/lib/kubelet' | xargs umount").Run()

	//删除之前kubeadm生成的配置文件目录 /etc/kubernetes
	resetConfigDir("/etc/kubernetes/")

	//删除文件目录/var/lib/kubelet 和 /var/lib/etcd
	dirsToClean := []string{"/var/lib/kubelet", "/var/lib/etcd"}
	fmt.Printf("Deleting contents of stateful directories: %v\n", dirsToClean)
	for _, dir := range dirsToClean {
		cleanDir(dir)
	}

	//停掉当前节点运行的所有k8s docker容器
	dockerCheck := preflight.ServiceCheck{Service: "docker"}
	if warnings, errors := dockerCheck.Check(); len(warnings) == 0 && len(errors) == 0 {
		fmt.Println("Stopping all running docker containers...")
		if err := exec.Command("sh", "-c", "docker ps | grep 'k8s_' | awk '{print $1}' | xargs docker rm --force --volumes").Run(); err != nil {
			fmt.Println("failed to stop the running containers")
		}
	} else {
		fmt.Println("docker doesn't seem to be running, skipping the removal of kubernetes containers")
	}

	return nil
}
```

小结：
kubeadm reset主要是回退当前节点在之前执行kubeadm init或者kubeadm join的执行结果。

## 五、kubeadm token分析
NewCmdToken()的实现在app/cmd/token.go里，与NewCmdInit()类似，它也是创建了一个cobra.Command类型的命令对象，并指定了该命令的相关参数；
与其他几个命令不同的是，NewCmdToken()方法会返回一个error；
看一下区别：

```
package cobra
import ... （略）

// Command is just that, a command for your application.
// eg.  'go run' ... 'run' is the command. Cobra requires
// you to define the usage and description as part of your command
// definition to ensure usability.
type Command struct {
... （略）
// Run: Typically the actual work function. Most commands will only implement this
Run func(cmd *Command, args []string)
// RunE: Run but returns an error
RunE func(cmd *Command, args []string) error
... （略）
}
```

该方法比较简单，如下：

```
package cmd
import ... （略）

func NewCmdToken(out io.Writer) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "token",
		Short: "Manage tokens used by init/join",

		// Without this callback, if a user runs just the "token"
		// command without a subcommand, or with an invalid subcommand,
		// cobra will print usage information, but still exit cleanly.
		// We want to return an error code in these cases so that the
		// user knows that their command was invalid.
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) < 1 {
				return errors.New("missing subcommand; 'token' is not meant to be run on its own")
			} else {
				return fmt.Errorf("invalid subcommand: %s", args[0])
			}
		},
	}
	//主要工作在这个NewCmdTokenGenerate()方法
	cmd.AddCommand(NewCmdTokenGenerate(out))
	return cmd
}

func NewCmdTokenGenerate(out io.Writer) *cobra.Command {
	return &cobra.Command{
		Use:   "generate",
		Short: "Generate and print a token suitable for use with init/join",
		Long: dedent.Dedent(`
			This command will print out a randomly-generated token that you can use with
			the "init" and "join" commands.

			You don't have to use this command in order to generate a token, you can do so
			yourself as long as it's in the format "<6 characters>.<16 characters>". This
			command is provided for convenience to generate tokens in that format.

			You can also use "kubeadm init" without specifying a token, and it will
			generate and print one for you.
		`),
		Run: func(cmd *cobra.Command, args []string) {
			//生成token
			err := RunGenerateToken(out)
			kubeadmutil.CheckErr(err)
		},
	}
}
//生成token
func RunGenerateToken(out io.Writer) error {
	s := &kubeadmapi.Secrets{}
	err := util.GenerateToken(s)
	if err != nil {
		return err
	}

	fmt.Fprintln(out, s.GivenToken)
	return nil
}
```

小结：
kubeadm token主要是可以事先生成一个token供init或join时使用。

## 六、kubeadm version分析
NewCmdVersion()的实现在app/cmd/version.go里，与NewCmdInit()类似，它也是创建了一个cobra.Command类型的命令对象，并指定了该命令的相关参数；
方法很简单，就是返回kubeadm的版本信息，如下：

```
package cmd
import ... （略）

func NewCmdVersion(out io.Writer) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Print the version of kubeadm",
		Run: func(cmd *cobra.Command, args []string) {
			//获取版本信息
			err := RunVersion(out, cmd)
			kubeadmutil.CheckErr(err)
		},
	}
	return cmd
}

func RunVersion(out io.Writer, cmd *cobra.Command) error {
	fmt.Fprintf(out, "kubeadm version: %#v\n", version.Get())
	return nil
}
```

其中version.Get()方法如下：

```
// Get returns the overall codebase version. It's for detecting
// what code a binary was built from.
func Get() Info {
	// These variables typically come from -ldflags settings and in
	// their absence fallback to the settings in pkg/version/base.go
	return Info{
		Major:        gitMajor,
		Minor:        gitMinor,
		GitVersion:   gitVersion,
		GitCommit:    gitCommit,
		GitTreeState: gitTreeState,
		BuildDate:    buildDate,
		GoVersion:    runtime.Version(),
		Compiler:     runtime.Compiler,
		Platform:     fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
	}
}
```

小结：
kubeadm version很简单就是获取kubeadm版本信息。

分析到此结束。