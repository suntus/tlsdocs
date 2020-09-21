# 摘要
该文档定义了TLS(Transport Layer Security)协议的1.3版本。TLS可以让C/S应用在互联网上通过一种能抵御信息泄露、破坏或篡改的方式安全通信。
该文档更新了RFC 5705和6066，废弃了RFC 5077、5246、6961。也对TLS1.2的实现做了些新的规定。

# 1. 简介
TLS的首要目标在两个通信端点之间提供一个安全通道；对底层传输通道的唯一要求就是传输可靠、没有乱序。具体来说，这个安全通道应该提供一下特性：
- 可鉴别：server端总是可被鉴别，client端可选被鉴别。鉴别可以通过非对称算法(比如RSA，ECDSA或者EdDSA)或者对称的预共享密钥(PSK)进行。
- 可信: 通道建立后传输的数据只能被两端看到。TLS不会隐藏传输数据的长度，但端点可以对TLS记录层进行填充，以此来隐藏实际长度，提高抵抗流量分析的能力。
- 完整性：通道建立后传输的数据一旦被攻击者篡改，就可以被检测到。

这些特性在面对那些完全掌握网络的攻击者的时候，应该也要保证是对的，见[RFC3552]。附录E对相关的安全特性有个更完整的说明。

TLS包含两个主要部分:
- 一个握手协议(#4)，负责鉴别通信实体、协商加密模式和参数、建立共享的密钥材料。握手协议被设计的可以抗篡改：一个主动攻击者是没有办法迫使通信双方协商出一个跟没有被攻击时不一样的参数的。
- 一个记录层协议(#5)，用握手协议建立的参数来保护通信双方的流量。记录层协议将流量分割成一系列的record，每个record都由通信密钥单独保护。

TLS是跟应用协议无关的: 更高层的协议可以透明的建立在TLS协议之上。但TLS标准并没规定应用协议怎么用TLS来增加安全性: 怎么初始化TLS握手、怎么处理交换的鉴别证书这些问题，被留给那些设计和实现应用协议的人去权衡。

本文档定义了TLS1.3版本。尽管TLS1.3跟之前的版本没有直接兼容，但所有版本的TLS会用一个版本协商机制来协商出一个两端共同支持的版本。

本文档取代和废弃了之前的TLS版本，包括TLS1.2[RFC5246]。也废弃了[RFC5077]中定义的ticket机制，用#2.2中的新机制替代。TLS1.3调整了密钥推导的方式，因此在#7.5中更新了[RFC5705]。它也在#4.4.2.1中调整了OCSP消息的携带方式，因此更新了[RFC6066]，废弃了[RFC7961]。

## 1.1 约定和术语
关键词*"MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECONMMENDED", "NOT RECOMMENDED", "MAY", "OPTIONAL"*按照[RFC2119][RFC8174]中描述的解释，当且仅当他们是大写的时候。

本文档会用到以下术语：
- client: 发起TLS连接的端点。
- connection: 两个端点之间的传输层连接。
- endpoint: connection中的client或server。
- handshake: client和server之间为建立TLS后续使用的参数进行的初始化协商。
- peer: 一个端点。当讨论一个具体端点的时候，"peer"指的是讨论中不是首要对象的另一个端点。
- receiver: 接收record的端点。
- sender: 发送record的端点。
- server: 不是发起TLS连接的端点。

## 1.2. 跟TLS1.2的主要区别
以下列出的是TLS1.2和1.3之间主要功能上的不同点，没有包括完全，另外还有很多其他细小的差别。
- 所有被认为过时的对称加密算法都从支持的列表中删除了，剩下的都是AEAD算法。加密套件的概念也变了，现在用来将认证和秘钥交换算法与记录层保护算法(包括秘钥长度)和一个在秘钥推导和MAC中用到的hash算法分开。
- 增加了一个0-RTT模式，为某些应用数据在连接建立的时候节省了一个往返的时间，但是牺牲了一定的安全性。
- 移除了静态RSA和DH算法套件；现在所有以公钥为基础的密钥交换机制都提供前向安全性。
- `ServerHello`之后的所有握手消息都被加密起来了。新添加的`EncryptedExtensions`消息让之前在`ServerHello`中明文传输的扩展项都得以保护起来。
- 重新设计了密钥推导函数。新设计的函数由于提高了密钥的独立性，更易于被密码学家分析。函数底层使用了HKDF算法。
- 重新组织了握手状态机，更具有一致性，然后移除了像`ChangeCipherSpec`这样多余的消息(有时候为了中间件的兼容性，还需要保留)。
- 现在椭圆曲线算法占主导地位，并加入了新的签名算法，比如EdDSA。TLS1.3移除了点格式的协商，对每种曲线，只取一种点格式。
- 其他密码学上的改进，比如调整了RSA padding算法，使用RSASSA-PSS填充。溢出了压缩、DSA算法和自定义的DHE族。
- 不推荐使用TLS1.2的版本协商机制，而是在扩展项中使用一个版本列表来做版本协商。这对现有的没有正确实现版本协商机制的server增加了兼容性。
- 带或不带服务端状态的会话恢复机制，还有之前TLS版本中存在的PSK加密套件，都被合并进了一个新的PSK交换机制中。
- 更新了引用，指向那些更新过版本的RFC(比如指向RFC 5280，而不是RFC 3280)。

## 1.3. 更新对TLS1.2的影响
本文档定义了几个可能会影响TLS1.2实现的改变，其中几项TLS1.3也不支持:
- #4.1.3节中定义的一个防止版本降级的机制
- #4.2.3中定义的RSASSA-PSS签名算法
- `ClientHello`扩展中的 "supported_versions" 可以用来协商TLS使用的版本，替换之前`ClientHello`中的 `legacy_version`字段
- "signature_algorithms_cert"扩展项允许client指明自己能哪些签名算法验证X.509证书。

另外，本文档阐述了几条对早期TLS版本的兼容性要求，见#9.3.

# 2. 协议总览
安全通道用到的加密参数由TLS握手协议产生。该TLS子协议由client和server首次通信的时候使用。握手协议允许两端协商协议版本、选择加密算法、可选进行双方认证和建立共享的密钥材料。一旦握手完成，两端就可以使用建立的key去保护应用层流量了。

握手失败或其他协议错误会导致连接中止，有时还可能先发送一个alert消息。

TLS支持的3个基本的密钥交换模式为：
- (EC)DHE(基于有限域或椭圆曲线的Diffie-Hellman)
- PSK-only
- PSK with (EC)DHE

```
      Client                                           Server

Key  ^ ClientHello
Exch | + key_share*
     | + signature_algorithms*
     | + psk_key_exchange_modes*
     v + pre_shared_key*       -------->
                                                  ServerHello  ^ Key
                                                 + key_share*  | Exch
                                            + pre_shared_key*  v
                                        {EncryptedExtensions}  ^  Server
                                        {CertificateRequest*}  v  Params
                                               {Certificate*}  ^
                                         {CertificateVerify*}  | Auth
                                                   {Finished}  v
                               <--------  [Application Data*]
     ^ {Certificate*}
Auth | {CertificateVerify*}
     v {Finished}              -------->
       [Application Data]      <------->  [Application Data]

        + : 表示消息中发送的重要的扩展项
        * : 表示可选的或依据不同情况发送的、不是每次都必须发送的消息或扩展项
        {}: 表示该消息用一个[sender]_handshake_traffic_secret中推导出来的key保护
        []: 表示该消息用一个[sender]_application_traffic_secret_N中推导出来的key保护

            图1: 完整握手的消息流
```

可以认为握手有3个阶段(上图显示的那样):
- 密钥交换: 建立共享密钥材料和选择加密参数。该阶段之后所有的消息都会被加密。
- server参数: 建立其他握手参数(client是否要被认证，应用层协议支持等等...)。
- 认证：认证server(和/或client)，提供key的确认和握手完整性校验。

