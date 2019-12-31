[TOC]


# 1. 简介
  TLS协议的主要目标是为两个应用之间的通信提供加密保护和数据完整性校验。该协议包括两层：TLS记录层协议和TLS握手层协议。TLS记录层在最下，工作在一些可靠的传输协议上(比如TCP)。记录层提供的连接安全性包括两个基本属性：
  - 连接是私密的。数据用对称加密算法加密(比如AES和RC4)。对称加密的密钥对每个连接来说是唯一的，且基于另一个协议（比如TLS握手协议）协商来的secret生成。记录层也可以不用加密就工作。
  - 连接是可靠的。每个消息传输的时候会包含一个使用密钥的MAC码来进行消息完整性校验。MAC码使用安全的hash算法（比如SHA-1等）计算得到。记录层协议不需要MAC码也能工作，但这通常只是用于另一个协议用记录层协议协商一些加密参数的情况下。

  TLS记录层协议用于加密多种更高层次的协议，其中一个就是TLS握手协议。握手协议让server和client能够相互认证，且在发送或接收第一个字节之前协商出一个加密算法和相应的密钥。TLS握手层协议提供的连接安全性包含3个基本属性：
  - 对端身份可以用非对称的或者说公钥加密的方法(比如RSA,DSA等)来进行认证。这种认证是可选的，但连接双方通常至少要求1个对端进行认证。
  - 共有密钥的协商是安全的：窃听者无法得到协商出的密钥，也无法获得任何建立好的连接的密钥信息。对中间人的攻击也是安全的。
  - 协商是可靠的：攻击者对协商的任何修改都能被通信双方所察觉。

  TLS的一个优势是应用层协议独立性。更高层的协议能够透明的使用TLS协议。但TLS标准没有规定应用层协议使用TLS去添加安全性，怎样初始化TLS握手和怎样判断交换的认证证书是否有效需要跑在TLS上层的协议的设计和实现者去决定。

## 1.2 跟TLS1.1的主要区别
  该文档是TLS1.1协议的一个修订版，包括增加协议的可扩展性，特别是加密算法协商的可扩展性。主要变化有：
  - 在伪随机算法（PRF, pseudorandom function）中的MD5/SHA-1组合被加密套件中规定的PRF替换掉了。本文档汇总所有的加密套件都用P_SHA256伪随机算法。
  - 数字签名中的MD5/SHA-1组合被一个单独的hash算法替换掉了。被签名元素现在包含一个指明使用什么hash算法的字段。
  - 对client和server可以接收哪种hash算法和哪种签名算法的部分做了大量的清理工作。这也导致了在签名和hash算法上的某些约束比上个TLS版本更宽松了。
  - 添加了使用其他数据模型的认证加密的支持。
  - 外部的TLS扩展项和AES加密套件的RFC现在合并进了TLS的RFC。
  - 对EncryptedPreMasterSecret版本号进行更严格的检查。
  - 严格化了一些要求。
  - Verify_data长度现在依据加密套件了(默认还是12字节)。
  - 清理了Bleichenbacher/Klima攻击防御的描述。
  - 现在很多情况下***必须***发送alert。
  - 收到一个certificate_request证书请求后，如果没有可用证书，client现在***必须***发送一个空的证书列表
  - TLS_RSA_WITH_AES_128_CBC_SHA加密套件必须实现。
  - 增加了HMAC-SHA256加密套件类。
  - 移除了IDEA和DES加密套件。他们现在过时了，会在单独的文件中说明。
  - 对接收SSLv2的hello的兼容性支持现在变成了***可以***，而不是***应该***，发送变成了***不应该***。将来对它的支持可能会变成***不应该***。
  - 表示语法增加了有限的"fall-through"描述，以方便多个地方都指向同一编码的情况。
  - 增加了一个实现陷阱章节。
  - 一般的澄清和编辑工作。

# 2. 目标
  TLS协议的目标，按照优先级如下：
  1. 密码学安全：TLS可以被用于在双方之间建立一个安全的通信通道。
  2. 互操作性：程序员开发的带TLS的程序可以跟另一个完全不知道代码的程序成功交换密码参数。
  3. 可扩展性：TLS希望能提供一个框架，让新的对称和非对称算法在需要的时候能添加进来。这也包括两个子目标：避免了设计一个新的协议(这会增加新的安全性缺陷被发现的可能)和避免实现一个全新的安全库。
  4. 相对高效：加密操作对CPU非常敏感，特别是非对称加密操作。基于此，TLS协议增加了一个可选的session缓存，来减少完整握手的次数。另外也要考虑减轻网络负载。

# 3. 本文档的目标
  本文档和TLS协议本身都是基于Netscape发布的SSL 3.0协议的。本协议和SSL 3.0之间没有太大的区别，但也足够让很多TLS和SSL 3.0协议的双方无法正常配合工作(尽管每个协议都有相应的兼容机制能回退到前一个版本)。本文档主要是给那些要实现TLS协议和做密码学分析的读者看的，在写的时候就考虑到了这两部分人的需求，因此很多算法相关的数据结构和规则都包含在了文档主体中(而不是在附录)，更方便查阅。
  本文档不会提供任何详细的服务或接口定义，但有些地方为了维持完整的安全性，也会包含一些要求的规则。

# 4. 表示语法
  本文档使用一种外部的表示语法来处理数据的格式化问题。下文是一些会被用到的非常基础和通用的语法。语法结构是从几种语法汇集的，包含了C语言和XDR标准的一些规定，但汇集太多也比较冒险。所以这个表示语法只用于TLS，不用于普遍使用。

# 4.1 基本块大小
  表示语法中数据项都是明确规定的。基本数据块大小是1个字节(8 bits)。多字节数据是字节从左到右、从上到下拼接起来的。对字节流来说，一个多字节项(例子中表示的是一个数字值)表示如下(使用C的标记)：
```
value = (byte[0] << 8*(n-1)) | (byte[1]) << 8*(n-2)) | ... | byte[n-1];
```
  多字节的值的字节序就是常见的网络字节序或者说大端格式。

# 4.2 杂项
  注释用"/\*"开头，用"\*/"结尾。

  可选部分用"[[]]"双括号括起来。

  包含无解释的单字节的项是opaque类型。

# 4.3 向量
  一个向量(一维数组)是一个同样类型数据组成的数据流。向量长度可以在文档中定义，也可以在运行时定义。不管用哪种方式，长度都指的是向量全部的字节数，而不是向量中元素的个数。用固定长度向量类型T可以定义一个新的类型T'如下：
```
T T'[n];
```
  这里向量类型T'有n个字节，n是T的大小的整数倍。向量的长度不包含在编码后的数据流中。
  下边这个例子中，Datum类型是协议中未解释的3个连续字节，Data类型是3个连续的Datum类型，总共包含9个字节。
```
opaque Datum[3]; /* three uninterpreted bytes */
Datum Data[9]; /* 3 consecutive 3 byte vectors */
```

  变长向量用一个合理的长度范围记号<floor..ceiling>(含两端)来定义。编码时，会将真正的向量长度放到内容字节前边。长度所占的字节数会保证能存放进最大长度的数值。一个实际长度字段是0的变长向量表示一个空向量。
```
T T'<floor..ceiling>;
```
  下面这个例子中，mandatory是一个必须包含300到400字节之间opaque类型的变长向量。永远不能为空。存放实际长度的字段需要用2个字节，也就是一个uint16类型，才能足够存进400这个值(uint16最大能存放2^16，但uint8只能存进256，所以至少需要2个字节，见4.4)。另外，longer类型最多能表示800字节的数据，或者说400个uint16类型，它可能为空，实际长度字段需要在编码后的向量前边占2个字节，编码后的向量实际长度必须是单个元素的偶数倍(比如一个元素类型是uint16的向量如果有17字节，就是不合法的)。
```
opaque mandatory<300..400>;
/* length field is 2 bytes, cannot be empty */
uint16 longer<0..800>;
/* zero to 400 16-bit unsigned integers */
```

# 4.4. 数值
  基础的数值类型是一个无符号的字节(uint8)。所有更大的数值类型都是按照4.1节所述的用固定长度的字节拼接起来的方法组成，同样也是无符号的。以下类型是提前定义的：
```
uint8 uint16[2];
uint8 uint24[3];
uint8 uint32[4];
uint8 uint64[8];
```
  本文档中所有的数值都按照网络字节序(大端)存储；16进制表示的01 02 03 04的uint32类型数值按10进制表示就是16909060。
  注意在一些情况下(比如DH参数)会需要将整数表示成opaque类型的向量，这时候他们表示无符号整数(比如，即使最高有效位被设置了，开始的0字节也是可以忽略的)。

# 4.5 枚举
  有多个数据类型可选择的类型叫枚举。一个枚举类型字段只能存放枚举中规定的类型中的一个。每定义一次都是一个不同的类型。只有相同类型的枚举值才能相互赋值或比较。枚举类型中的每个元素都要有个值，如下所示。枚举类型中的元素没有顺序，所以可以用任意顺序赋予它们唯一值。
```
enum { e1(v1), e2(v2), ... , en(vn) [[, (n)]] } Te;
```
  枚举值所占的字段长度需要能放下类型中规定的最大值。下边这个例子中需要1个字节来存放Color类型的值。
```
enum { red(3), blue(5), white(7) } Color;
```
  可以定义一个没有标签的冗余值来表示枚举类型需要占用多少字节(预留出足够的空间以便扩展)。
  下边这个例子中，Taste类型需要在编码后的消息中占据4个字节长度，虽然能使用的值暂时只有1,2,4.
```
enum { sweet(1), sour(2), bitter(4), (32000) } Taste;
```
  枚举值中元素的名称只在定义的类型中有效。在第1个例子中，完整的引用第二个元素的方法是 Color.blue，但也不是必须的：
```
Color color = Color.blue;   /* 完整引用 */
Color color = blue;         /* 隐含引用，也对 */
```
  对那些永远不会转换成外部数据的枚举类型来说，也可以省略掉数值信息。
```
enum { low, medium, high } Amount;
```

# 4.6. 结构体
  为了方便，基础类型可以组合起来变成结构体类型。每个定义都是新的、唯一的类型。结构体定义类似C的语法。
```
struct {
    T1 f1;
    T2 f2;
    ...
    Tn fn;
} [[T]];
```
  结构体中的字段可以用类似枚举值那样的引用语法，比如上个例子中T.f2表示第2个字段。结构体可以嵌套。

# 4.6.1 结构体变体
  定义的结构体可以在不同上下文中选择不同变体。选择判断的条件必须是枚举类型。对每个选择判断条件来说，都需要有一个对应的结构。选择之间可以有有限的顺延描述(fall-through)：如果两个选择之间没有其他情况，它们就可以对应相同的结构。下面例子中"orange"和"banana"都包含V2。注意这是TLS1.2的一个新语法。
  结构体变体可以用一个label引用。表示语法没有规定是否是运行时才决定使用哪种结构。
```
struct {
    T1 f1;
    T2 f2;
    ....
    Tn fn;
    select (E) {
            case e1: Te1;
            case e2: Te2;
            case e3: case e4: Te3;
            ....
            case en: Ten;
    } [[fv]];
} [[Tv]];
```
  例如：
```
enum { apple, orange, banana } VariantTag;

struct {
    uint16 number;
    opaque string<0..10>; /* variable length */
} V1;

struct {
    uint32 number;
    opaque string[10]; /* fixed length */
} V2;

struct {
    select (VariantTag) { /* value of selector is implicit */
        case apple:
            V1; /* VariantBody, tag = apple */
        case orange:
        case banana:
            V2; /* VariantBody, tag = orange or banana */
    } variant_body; /* optional label on variant */
} VariantRecord;
```

# 4.7. 加密属性
  5个加密操作——数字签名，流加密，块加密，带附加数据的认证加密，公钥加密——被分别设计成`digitally-signed, stream-ciphered, block-ciphered, aead-ciphered和public-key-encrypted`。在需要加密的字段前边加上相应的加密属性标签，就表示需要使用这种加密操作加密该字段。加密密钥隐含在当前session状态中(见6.1节)。

  数字签名元素被编码成DigitallySigned结构：
```
struct {
    SignatureAndHashAlgorithm algorithm;
    opaque signature<0..2^16-1>;
} DigitallySigned;
```

  `algorithm`字段表示用到的算法(该字段的定义见7.4.1.4.1节)。注意，这个版本的协议才引入`algorithm`字段。`signature`是用该算法计算出的对内容元素的签名。内容元素本身没有包含进来，只是计算了一下。`signature`的长度由签名算法和密钥决定。

  在RSA签名中，`opaque`类型向量包含使用在[PKCS1]中定义的`RSASSA-PKCS1-v1_4`签名模式生成的数字签名。按照[PKCS1]规定的，`DigestInfo`必须是DER编码[X680][X690]的。对没有参数的hash算法(包括SHA-1)，`DigestInfo.AlgorithmIdentifier.parameters`必须是NULL,但实现时候必须能处理没有`parameters`字段或者`parameters`字段为 NULL的情况。注意TLS早期协议中使用了不包括`DigestInfo`编码的RSA签名模式。

   在DSA中，20字节的SHA-1 hash值在数字签名算法操作中是直接使用的，没有其他hash操作参与。这生成两个值`r, s`。DSA签名是个`opaque`向量，内容格式用DER编码：
```
Dss-Sig-Value ::= SEQUENCE {
    r INTEGER,
    s INTEGER
}
```

  注意：在当前术语中，DSA指的是数字签名算法，DSS指的是NIST标准。在早期的SSL和TLS标准中，"DSS"是通用的。本文档用"DSA"表示算法，"DSS"表示标准，但在编码方面基于历史原因使用"DSS"。

  在流加密算法中，明文跟一个伪随机数生成器生成的密码学安全的随机数序列异或（XOR）。

  在块加密中，每个明文块被加密成密文块。所有的密文块使用CBC模式，块加密的所有项的大小是块加密长度的整数倍。

  在AEAD加密中，明文的加密和完整性校验同时进行。输入的明文可以是任意长度，AEAD加密后的数据通常比明文长一部分，因为要加上完整性校验。

  在公钥加密中，密钥对儿中的公钥用来加密，私钥用来解密。被公钥加密的消息元素编码为<0..2^16-1>的`opaque`向量，长度由加密算法和密钥决定。

  RSA加密使用[PKCS1]中定义的RSAES-PKCS1-v1_5加密模式进行。

  下边这个例子中：
```
stream-ciphered struct {
    uint8 field1;
    uint8 field2;
    digitally-signed opaque {
        uint8 field3<0..255>;
        uint8 field4;
    };
} UserType;
 ```

  内部结构体的字段(`field3`和`field4`)作为sign/hash算法的输入，然后整个结构体用流加密算法加密。该结构体的长度是2字节的`field1`和`field2`，加上2字节的sign/hash算法，加上2字节的签名的长度，加上签名算法结果的长度。签名的长度在编码和解码结构体之前已经由使用的算法和密钥提前得知。

## 4.8. 常量
  常量类型用于定义用于特定目的的类型和常量值。

  基础类型(opaque, 变长向量，包含opaque的结构体)不能被赋值。多元素结构体或向量中的所有字段都不能被省略。
  例如：
```
struct {
    uint8 f1;
    uint8 f2;
} Example1;

Example1 ex1 = {1, 4}; /* assigns f1 = 1, f2 = 4 */
```

# 5. HMAC和伪随机函数
  TLS记录层使用一个带密钥的消息认证码(MAC, Message Authentication Code)来保证消息的完整性。本文档中定义的加密套件使用一个叫HMAC的结构体，是基于hash的MAC，在[HMAC]中定义。其他加密套件如果需要，可以定义他们自己的MAC结构体。

  另外，为了能生成密钥和进行验证，需要一个能将密钥材料扩展成几个密钥材料的伪随机函数，该伪随机函数(PRF, pseudorandom function)输入一个密钥材料(secret)，一个种子(seed),一个标识符(id)，生成一个任意长度的随机数。

  本小节我们基于HMAC定义了一个PRF算法。带SHA-256 hash算法的本PRF用于本文档中的所有加密套件，也包括在TLS1.2协商的时候用到的、在本文档之前定义的那些加密套件。新的加密套件必须明确规定一个PRF算法和hash算法(常用SHA-256，也可以使用更安全的)。

  首先，我们定义一个消息扩展函数`P_hash(secret, data)`，用一个hash算法将一个密钥材料和一个种子扩展成任意长度的随机数串：
```
P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) +
                       HMAC_hash(secret, A(2) + seed) +
                       HMAC_hash(secret, A(3) + seed) + ...
```

  `+`表示拼接。
  `A()`定义为：

```
A(0) = seed
A(i) = HMAC_hash(secret, A(i-1))
```

  `P_hash`可以调用多次以生成需要长度的数据。例如，如果用`P_SHA256`来生成80字节的数据，需要调用3次(到`A(3)`)，共生成96字节的输出，然后丢掉最后的16字节，只要前80字节数据就行。

  TLS的PRF函数就是基于`P_hash`函数。
```
PRF(secret, label, seed) = P_<hash>(secret, label + seed)
```

label是个ASCII字符串，只包含字符主体，不包含字符串长度和结尾的null字符，比如"slithy toves"字符串用PRF处理时，输入是这样的：
```
73 6C 69 74 68 79 20 74 6F 76 65 73
```

# 6. TLS记录层协议

TLS记录层协议是个分层的协议。在每一层，消息会包含长度、描述、内容等字段。记录层协议负责接收应用层要发送的消息、消息分片、压缩(可选)，计算MAC，加密和传输密文。收到对端的消息后，解密、校验、解压缩、重组，然后传递给更高的应用层。

本文档中有4个协议使用记录层协议：握手协议，告警协议，ChangeCipherSpec协议和应用数据协议。因为TLS协议的可扩展性，还可以添加其他上层协议。新的记录层负载类型由IANA分配(见12节)。

具体实现禁止在没有协商过某些扩展功能时发送没有在本文档中定义的记录类型。如果收到了一个未知的记录类型，必须发送`unexpected_message`告警。

任何基于TLS设计的协议必须考虑到所有可能的攻击类型。这要求协议设计者必须清楚TLS提供和没提供哪些安全特性，不能依赖那些没提供的安全特性。

特别注意记录层的类型和长度没有被加密，如果这个信息本身很敏感，应用设计者会需要其他手段(填充，冗余传输)来减少该信息的泄露。

# 6.1. 连接状态

TLS的连接状态是TLS记录层协议工作的上下文环境。规定了压缩算法、加密算法、MAC算法，另外包括这些算法的一些参数：连接上读、写两个方向的MAC密钥和对称加密密钥。逻辑上讲，总会有4个连接状态：当前的读、写状态，未决的读、写状态。所有的记录包都要经过当前读、写状态的处理。未决状态的参数可以由握手协议来设置，ChangeCipherSpec协议可以决定是否用未决状态替换当前状态，替换的话，就拿未决状态替换当前状态，未决状态重新初始化为空状态。还没设置好加密参数的状态不能转换成当前状态。初始状态必须明确规定没有加密、压缩和MAC算法。

一个TLS连接的读写状态的加密参数有以下这些：

**连接端**: 在连接中本端点是"client"还是"server"。

**PRF算法**: 用于从主密钥(master secret)中生成密钥的算法(见5,6.3节)。

**对称加密算法**: 用于执行对称加密的算法。包含密钥长度，是块加密、流加密还是AEAD加密，加密算法的块大小(如果有的话)，明确或隐含的初始向量长度(iv或者nonce)。

**MAC算法**: 用于消息完整性认证的算法。包含MAC算法输出结果的长度。

**压缩算法**: 用于数据压缩的算法。包含压缩算法的所有信息。

**主密钥(master secret)**: 连接两端共有的一个48字节密钥。

**client random**: client提供的32字节随机数。

**server random**: server提供的32字节随机数。

这些参数用表示语法表示如下：
```
enum {server, client} ConectionEnd;
enum {tls_prf_sha256} PRFAlgorithm;
enum {null, rc4, 3des, aes} BulkCipherAlgorighm;
enum {stream, block, aead} CipherType;
enum {null, hmac_md5, hmac_sha1, hmac_sha256, hmac_sha384, hmac_sha512} MACAlgorithm;
enum {null(0), (255)} CompressionMethod;

struct {
    ConnectionEnd entity;
    PRFAlgorithm prf_algorithm;
    BulkCipherAlgorithm bulk_cipher_algorithm;
    CipherType cipher_type;
    uint8 enc_key_length;
    uint8 block_length;
    uint8 fixed_iv_length;
    uint8 record_iv_length;
    MACAlgorithm mac_algorithm;
    uint8 mac_length;
    uint8 mac_key_length;
    CompressionMethod compression_algorithm;
    opaque master_secret[48];
    opaque client_random[32];
    opaque server_random[32];
} SecurityParameters;
```

记录层会用这些加密参数生成以下6项(不是每个加密算法都需要所有的6个，不需要的项就为空):

- client 写时 MAC 的密钥
- server 写时 MAC 的密钥
- client 写时 的加密密钥
- server 写时 的加密密钥
- client 写时 的IV
- server 写时 的IV

client写时参数是server读时要用到的，反过来也一样。从加密参数中生成这6项的算法见6.3节。

一旦未决状态中的加密参数被设置、密钥被生成，就可以将未决连接状态转换成当前状态，每个经过处理的记录包都要更新当前状态，每个连接状态包含以下元素：

**压缩状态**: 压缩算法的当前状态。

**加密状态**: 加密算法的当前状态。包含专为当前连接生成的预定密钥。对流加密来说，这也会包含所有供流加密算法持续加解密的所有状态信息。

**MAC密钥**: 当前连接生成的MAC密钥。

**序列号(sequence number)**: 每个连接状态都包含一个序列号，由读、写状态分别维持。在状态刚激活时，序列号必须置0。序列号是个uint64类型的数，不能超过2^64-1。序列号不回绕，如果TLS连接需要回绕序列号，必须重新协商。每个记录包之后序列号递增：每个连接状态的第1个记录包的序列号必须是0.

# 6.2. 记录层
TLS记录层从上层接收不为空的任意长度的未定义数据。

# 6.2.1. 分片
记录层会将消息分片成`TLSPlaintext`中小于等于2^14字节大小的负载。记录层没有保存应用消息的边界(例如相同`ContentType`的多个消息可能会被塞进一个TLSPlaintext记录包中，或者一个消息可能分片成多个记录包)。
```
struct {
    uint8 major;
    uint8 minor;
} ProtocolVersion;

enum {
    change_cipher_spec(20),
    alert(21),
    handshake(22),
    application_data(23),
    (255)
} ContentType;

struct {
    ContentType type;
    ProtocolVersion version;
    uint16 length;
    opaque fragment[TLSPlaintext.length];
} TLSPlaintext;
```

**type**: 供更高层协议使用，指示包内负载的数据类型。

**version**: 使用的协议版本。本文档规定的是TLS1.2，使用`{3,3}`，`{3,3}`是从TLS1.0的`{3,1}`来的。注意client在没有收到ServerHello消息之前是不知道要使用的具体版本的。记录层要使用哪个版本号见附录E。

**length**: TLSPlaintext.fragment的字节数，长度不能超过2^14。

**fragment**: 负载数据。这部分数据对记录层来说是透明的，由`type`字段指定的相应的上层协议去处理。

具体实现 ***禁止*** 发送0内容长度的握手、告警、ChangeCipherSpec协议数据包，但 ***可以*** 发送0内容长度的应用数据包(会部分抵抗流量分析攻击)。

注意：不同TLS记录层负载类型可能会相互交错。应用数据类型消息通常比其他类型消息的传输优先级低一些，但必须按照加密的顺序传输记录包。第一个握手包发来之前接收者必须能接收处理交错的应用层数据包。

# 6.2.2. 记录帧压缩和解压缩
所有的记录帧都用当前会话状态定义的压缩算法压缩。总会有一个激活的压缩算法，但初始化时使用`CompressionMethod.null`。压缩算法将TLSPlaintext结构体转换成TLSCompressed结构体。当连接状态激活的时候，就用默认状态信息初始化压缩算法。[RFC3749]定义了TLS使用的压缩算法。

压缩必须是无损的，且增加的内容大小不能超过1024字节。如果`TLSCompressed.fragment`解压后的大小超过了2^14字节，必须报告一个解压失败的严重警告。
```
struct {
    ContentType type; /* same as TLSPlaintext.type */
    ProtocolVersion version;/* same as TLSPlaintext.version */
    uint16 length;
    opaque fragment[TLSCompressed.length];
} TLSCompressed;
```

**length**: `TLSCompressed.fragment`的长度，不能超过2^14+1024字节。

**fragment**: `TLSPlaintext.fragment`的压缩后的形式。

注意： `CompressionMethod.null`操作是一个实例，并没有调整字段结构(只是内容)。

实现细节：解压缩操作需要保证内部内存不会溢出。

# 6.2.3. 记录帧负载保护
加密和MAC算法将TLSCompressed结构体转换成TLSCiphertext结构体。解密算法反过来。记录帧MAC也会包含序列号，所以记录帧丢失、多余、重复都会被检测到。
```
struct {
    ContentType type;
    ProtocolVersion version;
    uint16 length;
    select (SecurityParameters.cipher_type) {
        case stream: GenericStreamCipher;
        case block: GenericBlockCipher;
        case aead: GenericAEADCipher;
    } fragment;
} TLSCiphertext;
```

**type**: 跟`TLSCompressed.type`一样。

**version**: 跟`TLSCompressed.version`一样。

**length**: `TLSCiphertext.fragment`的长度，不能超过2^14+2048字节。

**fragment**: 加密后的`TLSCompressed.fragment`，带MAC。

# 6.2.3.1. NULL或标准的流加密
流加密算法(包括`BulkCipherAlgorithm.null`，见附录A.6)将`TLSCompressed.fragment`结构转换成`TLSCiphertext.fragment`结构。
```
stream-ciphered struct {
    opaque content[TLSCompressed.length];
    opaque MAC[SecurityParameters.mac_length];
} GenericStreamCipher;
```

MAC生成过程如下：
```
MAC(MAC_write_key, seq_num +
                    TLSCompressed.type +
                    TLSCompressed.version +
                    TLSCompressed.length +
                    TLSCompressed.fragment);
```

"+"表示拼接。

**seq_num**: 该记录帧的序列号。

**MAC**： `SecurityParameters.mac_algorithm`指定的MAC算法。

注意MAC是在加密之前就计算的。流加密会加密包括MAC的整个明文数据。对不使用同步向量的流加密算法(比如RC4)，上一个数据包最后的流加密状态直接用于下一个数据包。如果加密套件是`TLS_NULL_WITH_NULL_NULL`，加密操作是一个空操作(数据不被加密，MAC大小是0，表示没有使用MAC)。对null加密和流加密来说，`TLSCiphertext.length`是`TLSCompressed.length`加上`SecurityParameters.mac_length`。

# 6.2.3.2. CBC块加密
对块加密算法(比如3DES,AES)来说，加密和MAC算法将`TLSCompressed.fragment`结构转换成`TLSCiphertext.fragment`结构。
```
struct {
    opaque IV[SecurityParameters.record_iv_length];
    block-ciphered struct {
        opaque content[TLSCompressed.length];
        opaque MAC[SecurityParameters.mac_length];
        uint8 padding[GenericBlockCipher.padding_length];
        uint8 padding_length;
    };
} GenericBlockCipher;
```

MAC的生成方法见6.2.3.1节。

**IV**: 初始向量(IV)应该随机选取，禁止可预测。注意在TLS1.1及之前的版本，是没有IV字段的，前一个记录帧的最后一个密文块被用作下一个记录帧的IV。添加该字段是为了抵抗[CBCATT]中描述的攻击。对块加密来说，IV的长度就是`SecurityParameters.record_iv_length`，等于`SecurityParameters.block_size`。

**padding**: 填充是为了让明文长度正好是块加密算法的块长度的整数倍。填充最多为255字节，只要能让`TLSCiphertext.length`正好是块长度的整数倍就行。超过最小长度的填充也是合理的，可以用来抵御流量分析攻击。填充的每个uint8字节的数值都必须是填充长度的值，接收者必须检查填充，检查到填充错误的话，需要报`bad_record_mac`告警。

**padding_length**: 填充长度必须保证让GenericBlockCipher结构的长度是块加密算法的块长度的整数倍。正确的长度值在0~255之间(含)。这个长度表示填充的长度，不包含该填充长度字段本身。

加密后的数据长度(`TLSCiphertext.length`)大于`SecurityParameters.block_length, TLSCompressed.length, SecurityParameters.mac_length 和 padding_length`之和。

举个栗子：如果`block_length`是8字节，数据内容长度是61字节(TLSCompressed.length)，MAC长度是20字节，那么填充前就是82字节(不包括IV)。因此，填充长度mod 8就必须等于6，好让填充后的长度正好是8字节(块加密的块大小)的整数倍，填充长度就可以是6, 14, 22, ..., 直到254。如果选择最小的值6，那么填充向量就是6字节，每个字节的数值都是6.因此GenericBlockCipher在块加密前的最后8字节就是`xx 06 06 06 06 06 06 06`，其中`xx`是MAC的最后一个字节。

注意：使用块加密的CBC模式的话，需要在发送密文之前就知道完整的明文(不能加密一部分，发送一部分)，否则就可能受到[CBCATT]中描述的攻击。

实现细节：Canvel et al.在[CBCTIME]中描述了一种根据计算MAC需要的时间来针对CBC填充操作的时间攻击。为了抵御这种攻击，实现的时候必须保证不管填充是正确还是不正确，对记录帧的处理时间都保持一样。通常做法是即使填充不正确，也进行MAC计算，然后拒绝掉这个包，比如，如果填充不正确，可以假设填充长度是0，继续计算MAC。由于MAC计算的时候会受数据帧的具体长度影响，这就会留下一个小的时间信道，但由于已存在的MAC比较大且这个时间信号相当小，该时间信道不足以被利用。

# 6.2.3.3. AEAD算法
对AEAD算法(CCM, GCM)来说，AEAD函数将`TLSCompressed.fragment`结构转换成AEAD的`TLSCiphertext.fragment`结构。
```
struct {
    opaque nonce_explicit[SecurityParameters.record_iv_length];
    aead-ciphered struct {
        opaque content[TLSCompressed.length];
    };
} GenericAEADCipher;
```

AEAD算法输入参数为一个key,一个nonce，一段明文，和一些需要在完整性校验中校验的附加数据(additional data)。该key是`client_write_key`或`server_write_key`。不需要MAC的key。

每个AEAD加密套件都必须明确指出怎么生成nonce和`GenericAEADCipher.nonce_explicit`部分的长度。很多时候都可以用[AEAD]的3.2.1节中描述的部分隐含nonce技术来做，这时候`record_iv_length`就是明确指出的这部分nonce的长度。这种情况下，nonce的隐含部分应该从`key_block`中生成(就是`client_write_iv`和`server_write_iv`)(见6.3节)，明确的部分包含在`GenericAEADCipher.nonce_explicit`。

明文就是`TLSCompressed.fragment`。

附加数据我们称作`additional_data`，定义如下：
```
additional_data = seq_num
                    + TLSCompressed.type
                    + TLSCompressed.version
                    + TLSCompressed.length;
```

`"+"`表示拼接。

`aead_output`字段包含AEAD加密操作输出的密文, 长度通常比`TLSCompressed.length`大一些，大多少由不同的AEAD加密套件决定。因为可能有填充，超出的部分会随不同的`TLSCompressed.length`不一样，但每个AEAD算法产生的密文超过的部分不能大于1024字节。
```
AEADEncrypted = AEAD-Encrypt(write_key, nonce, plaintext, additional_data);
```

要解密和校验，AEAD算法输入参数为key,nonce,附加数据和`AEADEncrypted`的值，或者输出明文，或者返回解密失败的错误，而没有单独的完整性校验操作。
```
TLSCompressed.fragment = AEAD-Decrypt(write_key, nonce,
                                    AEADEncrypted,
                                    additional_data)
```

如果解密失败，必须生成一个`bad_record_mac`的严重告警。

# 6.3. 密钥推导
记录层协议需要一个算法，能从握手协议协商出来的加密参数中生成当前连接状态使用的密钥。

主密钥会被扩展成一个安全的随机字符串，进而被分割成1个client write MAC key, 1个server write MAC key，1个 client write 加密 key, 1个server write 加密 key，顺序就是按照这个顺序。不使用的值就置空。一些AEAD算法会额外需要1个client write IV 和一个 server write IV(见 6.2.3.3)。

在key和MAC key生成过程中，主密钥起随机源的作用。

要生成密钥材料，需要计算
```
key_block = PRF(SecurityParameters.master_secret,
                "key expansion",
                SecurityParameters.server_random +
                SecurityParameters.client_random);
```

直到输出足够的长度。然后，`key_block`分割如下：
```
client_write_MAC_key[SecurityParameters.mac_key_length]
server_write_MAC_key[SecurityParameters.mac_key_length]
client_write_key[SecurityParameters.enc_key_length]
server_write_key[SecurityParameters.enc_key_length]
client_write_IV[SecurityParameters.fixed_iv_length]
server_write_IV[SecurityParameters.fixed_iv_length]
```

目前，按照[AEAD]3.2.1节所述，`client_write_IV`和`server_write_IV`只是用作nonce的隐藏部分。

实现细节：当前定义的用到密钥材料最长的是`AES_256_CBC_SHA256`，需要 2x32 字节的key，2x32字节的MAC key,总共是128字节的密钥材料。

# 7. TLS握手协议
TLS有3个子协议，用于为记录层协商对端的加密参数、自我认证、初始化协商的加密参数和相互报告错误。

握手协议主要负责协商出一个会话，包括以下各项：

**session identifier**: server选择的一个随机字符串用于标识一个活跃的或者可复用的会话状态。

**peer certificate**: 对端的X.509v3[PKIX]证书，状态的这个字段可能为空。

**compression method**: 加密前压缩数据的压缩算法。

**cipher spec**: 指定生成秘钥材料的伪随机函数(PRF)，对称加密算法(比如null, AES)，MAC算法(比如HMAC-SHA1)。也定义一些密码属性，比如`mac_length`。(标准格式见附录A.6)

**master secret**: client和server之间共享的48字节秘钥。

**is resumable**: 标记该会话是否能用于初始化一个新连接的标志。

这些项是记录层保护应用数据时用于创建加密参数的。很多连接其实可以用握手协议的会话恢复特性初始换相同的连接。

# 7.1. Change Cipher Spec协议
change cipher spec协议指示加密状态转换。该协议只包含1个消息，用当前连接状态(不是未决状态)加密和压缩。该消息只包含1个字节，值是1.
```
struct {
    enum {change_cipher_spec(1), (255)} type;
} ChangeCipherSpec;
```

client和server发送ChangeCipherSpec消息，以通知对端接下来的记录帧会用新协商的CipherSpce和key来保护(加密)。接收方会通知记录层立马将未决的读状态转换成当前状态。一旦发送该消息，发送方会立马通知记录层将未决写状态转换成当前写状态。(见6.1) ChangeCipherSpec消息在握手协商完加密参数之后、发送Finished消息之前发送。

注意：如果连接上发生重新握手，通信双方可能还会用旧的CipherSpec继续发送数据。但一旦发送了ChangeCipherSpec，就必须用新的CipherSpec了。首先发送ChangeCipherSpec的一端还不知道对端是否已经完成了新的秘钥材料的计算(例如对端需要执行一个比较耗时的公钥计算操作)。因此，接收方必须有一小段时间缓存收到的数据。实际上，现代机器上这段时间非常短，可以忽略不计。

# 7.2. 告警协议
TLS记录层支持的一种负载类型就是`alert`。告警消息传递告警的严重性(warning还是fatal)和描述。严重告警(fatal)会终止连接，这种情况下，对应该session的其他连接可能还会继续，但该session必须被标记为无效，防止再用该session新建连接。跟其他消息一样，告警消息也是使用当前连接状态来加密和压缩。
```
enum { warning(1), fatal(2), (255) } AlertLevel;

enum {
    close_notify(0),
    unexpected_message(10),
    bad_record_mac(20),
    decryption_failed_RESERVED(21),
    record_overflow(22),
    decompression_failure(30),
    handshake_failure(40),
    no_certificate_RESERVED(41),
    bad_certificate(42),
    unsupported_certificate(43),
    certificate_revoked(44),
    certificate_expired(45),
    certificate_unknown(46),
    illegal_parameter(47),
    unknown_ca(48),
    access_denied(49),
    decode_error(50),
    decrypt_error(51),
    export_restriction_RESERVED(60),
    protocol_version(70),
    insufficient_security(71),
    internal_error(80),
    user_canceled(90),
    no_renegotiation(100),
    unsupported_extension(110),
    (255)
} AlertDescription;

struct {
    AlertLevel level;
    AlertDescription description;
} Alert;
```

# 7.2.1. 关闭告警
client和server需要共享什么时候连接会终止的信息，以防止截断攻击。任一端都可以发起关闭连接的通知。

**close_notify**: 该消息通知对端我不会再发送其他消息了。注意跟TLS1.1类似，有些失败导致正常关闭后，并不要求该session不能再复用。这是自TLS1.0之后根据大量实践做的调整。

任一端都可以通过发送`close_notify`告警来关闭连接。关闭告警之后收到的任何数据都要忽略掉。

除非发送有其他fatal级别的告警，任一端在要关闭写方向上的连接时，都要发送`close_notify`告警，对端必须回复自己的`close_notify`告警，立即关闭连接，丢掉任何正在写的数据。不要求先发送关闭告警的一端必须等着对端的`close_notify`告警才能关闭自己的读连接。

如果使用TLS的应用协议支持在TLS连接结束后继续使用底层连接传输消息，那TLS就必须等着收到对端的`close_notify`，然后通知应用协议TLS连接确实正常关闭了。如果应用协议不会再传输其他消息，具体实现可以选择不等待`close_notify`而直接关闭底层连接。本标准不会让TLS考虑怎么去管理底层的传输(例如TCP连接)，包括连接什么时候打开和关闭。

注意：可以假设关闭连接时发送的数据在关闭底层连接前就可靠的传输出去了。

# 7.2.2. 错误告警
TLS握手协议中的错误处理非常简单。当检测到错误时，检测到的一端会给另一端发送一个消息。一旦发送或者收到一个严重告警消息，就立马关闭当前连接。server和client必须丢掉任何连接相关的session id、key、秘钥材料。所以，任何由于严重告警关闭的连接都不可被恢复。

不管遇到哪种严重告警的情况，实现的时候都要在关闭连接之前发送相应的告警信息。对那些没有明确定义告警等级的错误来说，发送方可以决定是要当做严重错误还是普通告警。如果实现的时候想在发送错误后直接关闭连接，那就要把该错误的等级设置为严重。

如果发送或收到了一个普通告警的错误消息，连接通常还正常进行。如果接收方决定不继续该连接(在收到了一个`no_renegotiation`告警后，它不接受)，就应该发送一个严重告警来终止该连接。这样的话，发送方通常就不知道接收方到底会采取哪种响应，所以，如果发送方希望继续连接，普通告警就没什么卵用。例如，如果一端想接受过期证书(可能是在跟用户确认后)继续正常连接，通常就不会发送`certificate_expired`告警了。


|错误告警定义如下||
|----------------------|-----------------------|
|**unexpected_message** | 收到了不合适的消息。总是严重等级，且不应该在通信的时候被观测到。|
|**bad_record_mac** | 收到的记录帧带的MAC不正确的时候发送的，也会在TLSCiphertext解密的时候，由于不是加密块的整数倍，或者填充不正确的原因发送。总是严重，且不应该在通信时被发现(除非消息在网络中被破坏)。|
| **decryption_failed_RESERVED**| 用于早期的TLS版本，可能会引起某些针对CBC模式的攻击。在兼容性实现中不应该被发送。|
| **record_overflow** | 收到的TLSCiphertext记录帧长度超过2^14+2048字节，或者解密后的TLSCompressed记录帧超过2^14+1024字节时，会发送该告警。总是严重告警，需要加密保护，不能在通信过程中被观察到。 |
| **decompression_failure** | 解压算法收到的输入不正确(比如解压后超过了规定的长度)。总是严重告警，需要加密保护，不能在通信过程中被观察到。 |
| **handshake_failure** | 收到该告警意味着对端无法协商出合适的加密参数，导致无法继续。严重告警。 |
| **no_certificate_RESERVED** | 只用于SSLv3，兼容性实现的时候不应该被发送。 |
| **bad_certificate** | 证书被破坏，包含的签名不正确等。 |
| **unsupported_certificate** | 不支持的证书类型。 |
| **certificate_revoked** | 证书被签发者收回了。 |
| **certificate_expired** | 证书过期或者还未投入使用。 |
| **certificate_unknown** | 处理证书过程中一些其他导致证书无法被接受的特殊情况。 |
| **illegal_parameter** | 握手中的一个字段跟其他字段不一致。总是严重告警。 |
| **unknown_ca** | 收到了完整的或部分的证书链，但找不到CA证书或者CA没有被一个已知可信的CA签名。总是严重告警。 |
| **access_denied** | 收到了正确的证书，但由于有接入控制，就发送该告警表示不继续协商了。总是严重告警。 |
| **decode_error** | 有些消息因为某些字段超过了规定范围或消息长度不准确，就会发送该消息。总是严重告警，需要加密保护，不能在通信过程中被观察到。 |
| **decrypt_error** | 握手加密算法操作失败，包括无法正确验签或者无法检验Finished消息的正确性。总是严重告警。 |
| **export_restriction_RESERVED** | 在早期TLS版本中使用，现在不再用。 |
| **protocol_version** | 识别到了client发送来的协议，但server端不支持。(比如因为安全问题不支持一些旧的版本。)总是严重告警。 |
| **insufficient_security** | 在server需要更安全的加密算法时，不是发送`handshake_failure`，而是发送该告警。总是严重告警。 |
| **internal_error** | 跟对端或者协议正确性不相关的内部错误(比如内存申请失败等)导致连接无法继续。总是严重告警。 |
| **user_canceled** | 由于跟协议失败不相关的原因希望取消握手，如果握手完成后，用户想取消，更合适的是发送一个`close_notify`消息。该告警后边应该跟个`close_notify`。通常是warning级别。 |
| **no_renegotiation** | client收到hello request之后响应，或者server在第一次握手后再收到client hello后响应。不管哪种情况通常都导致重新协商，当接收端觉得不合适的话，就会发送该告警。这种情况下，对端会决定要不要继续连接。举个例子，server可能会另起一个进程来满足连接请求，该进程在开始时会收到一些加密参数(秘钥长度，认证方法等)，这之后就很难再更改这些参数了，这时候如果client想重新协商，server就可以发送该告警。总是warning级别。 |
| **unsupported_extension** | client收到server hello中包含不是对client hello中扩展项回复的扩展项的时候，会发送该消息。总是严重告警。 |

新的Alert消息由IANA管理。

## 7.3. 握手协议总览
会话状态的加密参数由工作在TLS记录层之上的握手协议产生。当client和server初次通信的时候，他们协商出一个协议版本、对称加密算法、相互认证的方式和用于生成共有密钥的非对称加密算法。

TLS握手协议有以下几步：
- 交换hello消息来协商算法，交换随机数，检查会话恢复。
- 交换必要的加密参数好让client和server协商出一个预主密钥。
- 交换证书和加密算法信息好让client和server认证自己。
- 用预主密钥和交换的随机数来产生一个主密钥。
- 给记录层提供加密参数。
- 让client和server确认对端产生了同样的加密参数，并确认握手没有被攻击者篡改。

注意更高层的应用不应该完全信任TLS会协商出尽可能安全的连接。中间人攻击有很多方法可以让两端使用它们支持的最不安全的算法。协议在设计时就尽量减少这方面的风险，但还是会被攻击：例如，攻击者可能阻断了安全服务运行的端口，或者让两端协商出未认证的连接。上层应用的一个基础原则是必须知道他们的安全要求底线在哪里，不在安全底线之下的通道上传输敏感信息。TLS协议在加密算法套件提供的安全等级上是安全的：如果你跟一个认证过证书的host协商出了3DES和1024位的RSA，你可以认为该通道是安全的。

这些目标由握手协议实现，握手协议可以总结如下：client发送`ClientHello`消息，server必须回复一个`ServerHello`消息，或者回复一个严重错误，让连接失败。`ClientHello`和`ServerHello`会在client和server之间协商出部分加密参数：协议版本，session ID， 加密套件，压缩算法。另外产生和交换两个随机参数：`ClientHello.random`和`ServerHello.random`。

真正的密钥交换最多用到了4个消息：server的`Certificate，ServerKeyExchange`，client的`Certificate, ClientKeyExchange`。可以通过为这些消息定义新的格式和用法来添加新的密钥交换方法，以让client和server协商出预主密钥。预主密钥必须足够长，当前定义的密钥交换算法协商出的预主密钥大于等于46字节。

hello消息之后，如果需要server端认证，server会在`Certificate`消息中发送自己的证书。另外如果需要可能会发送`ServerKeyExchange`消息(比如，如果server没有证书，或者它的证书只用于签名)。如果server已被认证，如果协商出的加密套件允许，它可能会要求client也发送证书，接下来，serverhi发送`ServerHelloDone`表示握手的hello消息阶段已经完成了。server会等着client的回复。如果server发送了`CertificateRequest`，client必须回一个`Certificate`消息，然后发送`ClientKeyExchange`消息，该消息的内容由`ClientHello`和`ServerHello`协商出的非对称加密算法决定。如果client发送了可以用于签名的证书，就会再发送一个`CertificateVerify`消息表明确实拥有证书中公钥对应的私钥。

这时，client会发送`ChangeCipherSpec`消息，将未决状态转换成当前激活状态，并在新的加密状态下立即发送`Finished`消息。server必须回复自己的`ChangeCipherSpec`消息，将未决状态转换成当前激活状态，并在新的加密状态下发送`Finished`消息。在这里，握手就完成了，client和server就可以开始传输应用层数据了。(见下边的流程图。)应用数据在初次握手完成前禁止发送(除`TLS_NULL_WITH_NULL_NULL`加密套件)。

```
Client                          Server
ClientHello         -------->
                                ServerHello
                                Certificate*
                                ServerKeyExchange*
                                CertificateRequest*
                    <--------   ServerHelloDone
Certificate*
ClientKeyExchange
CertificateVerify*
[ChangeCipherSpec]
Finished            -------->
                                [ChangeCipherSpec]
                    <--------   Finished
Application Data    <------->   Application Data

图1. 完整握手消息流
```

\* 表示可选的或者根据情况并不总是发送的消息

注意: 为了避免流水线停顿，`ChangeCipherSpec`是一个单独的TLS协议，不是一个握手消息。

当client和server决定恢复之前的一个会话或者复用现有的会话(而不是重新协商加密参数)，消息流如下：

client将要恢复的session的session ID放到`ClientHello`中发送出去，server检查它自己的session cache中是否有该session，如果找到了，server会在指定的session状态中重建连接，会发送带有相同session ID的`ServerHello`消息。这时，client和server都必须发送`ChangeCipherSpec`消息然后直接发送`Finished`。一旦重新连接建立完成，client和server就可以开始传输应用层数据了。(见如下流程图。)如果没找到匹配的session ID， server会新生成一个session ID，client和server就进行完整握手。
```
Client                          Server
ClientHello         -------->
                                ServerHello
                                [ChangeCipherSpec]
                    <--------   Finished
[ChangeCipherSpec]
Finished            -------->
Application Data    <------->   Application Data
图2。 简短握手消息流
```
每个消息的内容和特点会在下边章节中详细说明。

## 7.4. 握手协议
TLS握手协议是定义在记录层之上的一个协议。该协议用于协商会话的加密参数，握手消息由记录层提供，被封装在一个或多个`TLSPlaintext`结构中，由当前激活的会话状态处理和传输。
```
enum {
    hello_request(0), client_hello(1), server_hello(2),
    certificate(11), server_key_exchange (12),
    certificate_request(13), server_hello_done(14),
    certificate_verify(15), client_key_exchange(16),
    finished(20), (255)
} HandshakeType;

struct {
    HandshakeType msg_type; /* handshake type */
    uint24 length;          /* bytes in message */
    select (HandshakeType) {
        case hello_request: HelloRequest;
        case client_hello: ClientHello;
        case server_hello: ServerHello;
        case certificate: Certificate;
        case server_key_exchange: ServerKeyExchange;
        case certificate_request: CertificateRequest;
        case server_hello_done: ServerHelloDone;
        case certificate_verify: CertificateVerify;
        case client_key_exchange: ClientKeyExchange;
        case finished: Finished;
    } body;
} Handshake;
```

下面按照握手协议消息必须出现的顺序进行详细介绍。不按顺序发送的握手消息会导致严重告警。但是不需要的握手消息可以忽略。注意顺序上有个例外：`Certificate`消息在握手中会用到两次(从server到client和从client到server)，但只在第一次出现的时候说明一次。只有1个消息不受顺序规则的约束，那就是`HelloRequest`消息，它可以在任何时候被发送，但在握手中间收到的话，client应该忽略掉它。

新的握手消息由IANA管理。

### 7.4.1. hello消息
hello阶段的消息用于在client和server之间交换加密参数。开始一个新会话时，记录层连接状态的加密、hash、压缩算法都初始化为null。当前连接状态用于重新协商的消息。

# 7.4.1.1. Hello Request
该消息发送的时机：server在任何时候都可能发送该消息。

该消息的含义：`HelloRequest`只是简单的通知client应该开始一个新的协商过程。作为回应，client应该在合适的时候发送`ClientHello`消息。该消息不是为了区分哪一端是server哪一端是client，只是为了发起新协商过程。server不应该在client刚开始连接的时候就立即发送`HelloRequest`，那是client需要发送`ClientHello`的时候。

如果client当前正在协商会话，client可能会忽略该消息。client不想协商新会话的话，或者默默忽略该消息，或者发送一个`no_renegotiation`告警。因为握手消息要先于应用数据发送，可以认为协商在收到client发来的没几个记录帧之后就能很快开始。如果server在发送了`HelloRequest`后没收到`ClientHello`，可以用一个严重告警来关闭连接。

发送`HelloRequest`之后，server在握手协商完成之前不应该再重复发送。

该消息的结构：
```
struct {} HelloRequest;
```

该消息不会被包含进用于`Finished`和`CertificateVerify`消息的握手hash中。

#### 7.4.1.2. Client Hello
该消息发送的时机：当client初次连接server时，需要发送`ClientHello`作为第一个消息。client也可能再回应`HelloRequest`或者恢复一个已有连接的时候发送该消息。

该消息的结构：
`ClientHello`包含一个随机数结构体，之后的协议也会用到。
```
struct {
    uint32 gmt_unix_time;
    opaque random_bytes[28];
} Random;
```
**gmt_unix_time**: 根据发送者内部的时钟确定的当前标准时间(从1970.1.1 0点开始的秒数，忽略闰秒)。基础的TLS协议并没规定一定要设置准确的时间，更高层的协议可能会有更高的要求。注意，由于历史原因，字段名称叫GMT，是现在广泛使用的UTC的前身。

**random_bytes**: 28字节的安全随机数。

`ClientHello`消息包含一个变长的session标识，如果不为空，该值表示同一个client和server之间希望重新使用的session加密参数。该session ID可能来自一个更早的连接、当前连接、或者另一个当前活跃的连接。第二个选项在client只想更新随机数和主密钥的时候很有用，第三个选项可以不用重复进行完整握手就建立多个不相关的安全连接通道。这些独立的连接可以串行或并行产生；一个`SessionID`可以在完整握手校验完`Finished`消息后就一直存在，直到过期或者与之相关的session产生了一个严重错误。`SessionID`的实际内容由server定义
```
opaque SessionID<0..32>;
```

注意：由于`SessionID`没被加密和用MAC保护，server不应该在里边放一些敏感信息或者因为里边的消息被修改而引起安全问题。(注意整个握手的消息，包括`SessionID`都会在握手最后由`Finished`保护起来。)

`ClientHello`消息中的加密套件列表，由client发送给server，包含client支持的加密算法套件(按照client期望的顺序从前到后)。每个加密算法套件定义一个密钥交换算法、一个对称加密算法(包括密钥长度)、一个MAC算法和一个PRF算法。server会选择一个支持的加密套件，或者没有支持的，就返回一个握手失败然后关闭连接。如果列表包含server不认识、不支持或者不希望使用的套件，server必须忽略这些，继续往下处理。
```
uint8 CipherSuite[2]; /* Cryptographic suite selector */
```

`ClientHello`包含一个client支持的压缩算法列表，按照优先级从前到后排列。
```
enum { null(0), (255) } CompressionMethod;

struct {
    ProtocolVersion client_version;
    Random random;
    SessionID session_id;
    CipherSuite cipher_suites<2..2^16-2>;
    CompressionMethod compression_methods<1..2^8-1>;
    select (extensions_present) {
        case false:
            struct {};
        case true:
            Extension extensions<0..2^16-1>;
    };
} ClientHello;
```

TLS允许在`compression_methods`字段之后跟一个扩展项字段。是否有扩展项可以通过检查`compression_methods`之后是否到`ClientHello`消息结尾了来确定。这个检查可选字段的方法跟TLS平常用的通过一个单独的长度字段来确定的方法不一样，是为了跟之前扩展项还没定义的TLS协议兼容。

**client_version**: 该会话期间client希望使用的TLS协议版本。应该时client支持的最新版本。对本文档来说，应该是3.3(后向兼容性的详细说明见附录E)。

**random**: client生成的随机数。

**session_id**: client希望在这次连接中使用的会话的ID，如果没有可用的`session_id`或者client希望重新生成新的加密参数，就将该字段置为空。

**cipher_suites**: client提供的加密套件列表，按照优先级从前往后。如果`session_id`字段不为空(希望进行会话恢复)，该列表中必须包含至少1个要恢复的会话中的加密套件。值见附录A.5。

**compression_methods**: client支持的压缩算法列表，按照优先级从前往后。如果`session_id`字段不为空(希望进行会话恢复)，该列表中必须包含至少1个要恢复的会话中的压缩算法。所有符合TLS协议的具体实现中的该列表都必须支持`CompressionMethod.null`。这样，client和server总能至少协商出1个压缩算法。

**extensions**: client可能会在扩展项字段中要求server的一些扩展功能。具体的`Extension`格式见 7.4.1.4。

如果client要求一些额外的功能，但server不支持，client可能会中止握手。带和不带扩展项的`ClientHello`server都要能接受，并且(对其他消息也一样)必须精确检查消息长度是否符合这些扩展项字段的具体格式，如果不符合，必须发送一个严重的`decode_error`告警。

发送`ClientHello`之后，client会等着一个`ServerHello`消息。除了`HelloRequest`，server回复的任何其他消息都认为是严重错误。

#### 7.4.1.3. Server Hello
该消息发送的时机：server在收到`ClientHello`之后，如果能协商出一套加密算法来，就回复该消息。如果不能协商出来，就回复一个握手失败的告警。

该消息的结构：
```
struct {
    ProtocolVersion server_version;
    Random random;
    SessionID session_id;
    CipherSuite cipher_suite;
    CompressionMethod compression_method;
    select (extensions_present) {
        case false:
            struct {};
        case true:
            Extension extensions<0..2^16-1>;
    };
} ServerHello;
```
是否有扩展项字段可以通过检查该消息在`compression_method`字段之后是否还有数据来判断。

**server_version**: 该字段是server选出的、小于client建议的、server支持的最大的协议版本号。本文档规定的协议版本号值为3.3（后向兼容性见附录E）。

**random**: server生成的随机数，必须跟`ClientHello.random`独立生成。

**session_id**: 对应该连接的session的ID。如果`ClientHello.session_id`不为空，server需要从session缓存中查找是否有该session。如果找到了，server也希望用该session建立新连接，会回复一个跟client提供的一样的值，这意味着会复用一个session，且直接去处理`Finished`消息。如果server不想缓存该session，就会回复一个空的`session_id`，因此该session也不会被复用。如果复用了一个session，必须使用最初完整握手成功的加密套件。注意没有要求server必须能够复用任何它之前发出去的`session_id`对应的session，因此client必须能够在任何时候都准备好进行完整握手。

**cipher_suite**: server从`ClientHellol.cipher_suites`列表中选出的1个加密套件。对于恢复的会话，该字段是要恢复的session中的。

**compression_method**：server从`ClientHello.compression_methods`列表中选出的1个压缩算法。对于恢复的会话，该字段是要恢复的session中的。

**extensions**: 扩展项列表。注意必须是client提供的扩展项才会出现在server的回复中。

##### 7.4.1.4. Hello Extensions
扩展项的格式为：
```
struct {
    ExtensionType extension_type;
    opaque extension_data<0..2^16-1>;
} Extension;

enum {
    signature_algorithms(13), (65535)
} ExtensionType;
```

这里：
- "extension_type"表示指定的扩展项类型。
- "extension_data"包含该扩展项的相关信息。

最初的扩展项集合定义在[TLSEXT]中，扩展项类型列表由IANA维护。

`ServerHello`中出现的扩展项类型必须是对应的`ClientHello`中有的。如果client收到了一个没有在`ClientHello`中发出的扩展项类型，必须用`unsupported_extension`严重告警终止握手。

但是，该框架中也可以支持将来某些"面向server"的扩展项。比如说扩展项x可能会要求client在`ClientHello`中发送一个空`extension_data`字段的该扩展项，表示client支持该扩展项，server可以根据需要返回响应。

`ClientHello`或`ServerHello`中出现多个类型的扩展项时，顺序随意。但每种类型最多只能有1个扩展项。

最后，注意扩展项可以在开始一个新session或者要求复用一个session时使用。实际上，client要求会话复用的时候通常不知道server是否会接受该请求，因此就必须准备进行完整握手的足够的扩展项。

通常，每种扩展项在定义的时候都需要描述在完整握手和会话复用时分别有什么影响。当前大部分扩展项都只跟会话初始化相关：当恢复一个旧的会话时，server不处理`ClientHello`中的扩展项，也不会在`ServerHello`中回复。但有些扩展项却会在会话恢复的时候起作用。

在协议中新旧特性之间可能会存在一些微妙(或者不微妙)的相互影响，导致整体安全性出现重大漏洞，在设计新扩展项的时候要考虑到下面这些方面：
- 有些server不支持的扩展项是错误，但有些仅仅是拒绝提供这种特性。通常，前者需要回错误告警，后者就只在server的扩展项中回复一下。
- 扩展项在设计的时候应该尽量考虑能抵抗使用或不使用某种特性的攻击(通过修改握手消息)。不管一个特性是否会引起安全问题，都应该遵循该原则。
  通常扩展项字段会包含进最后`Finished`消息的hash中，这一般就足够了，但也要考虑到改变扩展项字段的意义这种极端情况。协议设计和实现者需要牢记，在握手被确认之前，主动攻击者是能篡改消息，插入、删除、替换扩展项的。
- 用扩展项在技术上来讲是能改变TLS的主体设计的，比如加密套件协商的设计。但不推荐这样做，更好的办法是定义一个新的版本——特别是由于握手算法有基于版本号的防降级攻击的机制，版本回退是任何主设计改变要考虑的一个主要方面。

###### 7.4.1.4.1. 签名算法
client用`signature_algorithms`扩展项指导server使用哪个签名/hash算法对儿做数字签名。`extension_data`字段包含`supported_signature_algorithms`。
```
enum {
    none(0), md5(1), sha1(2), sha224(3), sha256(4), sha384(5),
    sha512(6), (255)
} HashAlgorithm;

enum { anonymous(0), rsa(1), dsa(2), ecdsa(3), (255) } SignatureAlgorithm;

struct {
    HashAlgorithm hash;
    SignatureAlgorithm signature;
} SignatureAndHashAlgorithm;

SignatureAndHashAlgorithm supported_signature_algorithms<2..2^16-2>;
```

每个`SignatureAndHashAlgorithm`的值表示一个client希望验签时使用的签名/hash算法对儿。整个列表按照优先级从前到后。

注意：因为不是所有的签名算法和hash都会被具体实现接受(比如DSA和SHA-1，而不是和SHA-256)，所以算法都是成对儿列出的。

**hash**: 要用到的hash算法。值可以有无hash、MD5、SHA-1、SHA-224、SHA-256、SHA-384、SHA-512。`none`是为了将来的扩展，比如一个签名算法不需要签名前hash。

**signature**: 要用到的签名算法。包括无签名、RSASSA-PKCS1-v1_5、DSA、ECDSA。`anonymous`在这里无意义，也不应该存在于该扩展中，只用于7.4.3.节。

该扩展项的语义有些复杂，因为加密套件规定了签名算法，但没规定hash算法，7.4.2和7.4.3描述了相应的规则。

如果client只支持本节列出的默认hash和签名算法，可以省略掉`signature_algorithms`扩展项。如果client不支持默认算法，或者支持其他一些(并且希望server在发送`Certificate`和`ServerKeyExchange`的时候优先使用)，就必须发送该扩展项。

如果client没发送该扩展项，server的处理如下：
- 如果协商的密钥交换算法是(RSA, DHE_RSA, DH_RSA, RSA_PSK, ECDH_RSA, ECDHE_RSA)中的一个，按照client发送了{sha1, rsa}处理。
- 如果协商的密钥交换算法是(DHE_DSS, DH_DSS)中的一个，按照client发送了{sha1,dsa}处理。
- 如果协商的密钥交换算法是(DHE_ECDSA, ECDHE_ECDSA)中的一个，按照client发送了{sha1, ecdsa}处理。

注意：TLS1.1没有明确的规定，这是一个变化。但考虑到实际，可以认为对端支持MD5和SHA-1。

注意：该扩展项对TLS1.2之前的协议无意义。client在协商之前的版本时禁止发送该扩展项。但如果client真的发送了，按照[TLSEXT]中的规则，server应该忽略掉它不认识的扩展项。

server禁止发送该扩展，server必须支持接收该扩展项。

当执行会话回复的时候，该扩展项不会包含在`ServerHello`中，如果`ClientHello`中有，server会忽略掉。

###### 7.4.2. Server Certificate
该消息发送的时机：只要server选择的密钥交换算法使用证书来进行认证(本文档中除DH_anon之外的所有其他密钥交换算法)，就必须发送该消息。该消息总会直接跟着`ServerHello`。

该消息的含义：消息承载的是server发给client的证书链。

证书必须跟协商好的加密套件的密钥交换算法和任何其他扩展功能相一致。

该消息的结构：
```
opaque ASN.1Cert<1..2^24-1>;

struct {
  ASN.1Cert certificate_list<0..2^24-1>;
} Certificate;
```

**certificate_list**: 是个证书链。发送者的证书必须在第一个。每个后边的证书都对紧挨着的前边一个进行签名认证。因为证书认证过程要求根证书独立分发，在假设对端已经有自签名的根证书之后，证书链中可以省去根证书。

client给证书请求回复时会用一样的消息类型和结构。注意如果client没有合适的证书，就不会发送该消息。

注意：PKCS7不再用于定义此处证书向量结构，因为没有用PKCS6中的扩展证书。另外，PKCS7定义的是个集合，不是个列表，会让证书的解析更困难。

server发送什么证书依赖下边的规则：
- 证书类型必须是X.509v3, 除非另外明确协商(比如[TLSPGP])。
- 终端证书的公钥(和相应约束)必须跟密钥交换算法相一致：

**密钥交换算法    -----       证书公钥类型**
**RSA/RSA_PSK**： RSA公钥；证书必须允许公钥用于加密(如果公钥使用约束扩展项存在，必须设置`keyEncipherment`)。RSA_PSK定义在[TLSPSK]中。

**DHE_RSA/ECDHE_RSA**: RSA公钥；证书必须允许公钥用于签名(如果公钥使用约束扩展项存在，必须设置`digitalSignature`)，并且签名/hash算法必须包含进`ServerKeyExchange`消息中。

**DHE_DSS**: DSA公钥；证书必须允许公钥可以用于`ServerKeyExchange`消息中的签名算法。

**DH_DSS/DH_RSA**: DH公钥；如果有公钥使用扩展项，必须设置`keyAgreement`。

**ECDH_ECDSA/ECDH_RSA**: 可用于ECDH的公钥；公钥必须用client支持的曲线和点，见[TLSECC]。

**ECDHE_ECDSA**: 可用于ECDSA的公钥；证书必须允许公钥可以用于`ServerKeyExchange`消息中的签名算法。公钥必须用client支持的曲线和点，见[TLSECC]。

- "server_name"和"trusted_ca_keys"扩展项用于指导证书选择。

如果client提供了"signature_algorithms"扩展项，那么server提供的所有证书都必须用该扩展项中的一对儿hash/签名算法对签名。注意，这意味着包含一个签名算法对应秘钥的证书可能用另一种签名算法来签名自身(比如一个RSA的公钥被一个DSA算法签名)。TLS1.1及之前这两个算法还是同一个，之后就分开了。这也表示，DH_DSS,DH_RSA,ECDH_ECDSA,ECDH_RSA秘钥交换算法不强制要求用于证书的签名算法是哪个。固定的DH证书可能使用该扩展项中的任何一个hash/签名算法对签名。DH_DSS,DH_RSA,ECDH_ECDSA,ECDH_RSA这些名字是因为历史原因才这样叫。

如果server有多个证书，就按照上边的条件选择一个(还有其他一些条件，比如传输层端点，本地配置和优先级等等)。如果server只有1个证书，应该尽量让其满足这些条件。

注意，有些证书使用的算法或者算法组合当前不能用于TLS，比如RSASSA-PSS签名秘钥(在`SubjectPublicKeyInfo`结构中OID是`id-RSASSA-PSS`)就不行，因为当前TLS没定义对应的签名算法。

如果加密套件定义了新的秘钥交换方法，也需要相应的规定证书格式和需要的秘钥编码信息。

### 7.4.3. ServerKeyExchange
消息发送的时机：会在server发送完`Certificate`之后立马发送(如果是匿名协商，就是`ServerHello`消息之后)。
该消息只会在server发送的`Certificate`消息(如果发送)中没有包含足够让client交换预主秘钥的信息的时候才会发送。下面这些秘钥交换算法就需要发送该消息：
**DHE_DSS**
**DHE_RSA**
**DH_anon**

下面这些秘钥交换算法不能发送该消息：
**RSA**
**DH_DSS**
**DH_RSA**

其他秘钥交换算法必须明确是否要发送该消息；如果发送，消息中包含的内容都是什么。

该消息的含义：该消息包含让client传输预主秘钥的加密信息：一个让client能完成秘钥交换的DH公钥(结果作为预主秘钥)或者其他算法的公钥。

该消息的结构：
```
enum { dhe_dss, dhe_rsa, dh_anon, rsa, dh_dss, dh_rsa
         /* may be extended, e.g., for ECDH -- see [TLSECC] */
    } KeyExchangeAlgorithm;

struct {
       opaque dh_p<1..2^16-1>;
       opaque dh_g<1..2^16-1>;
       opaque dh_Ys<1..2^16-1>;
} ServerDHParams;     /* Ephemeral DH parameters */
```

**dh_p**: DH算法的prime modulus。
**dh_g**: DH算法的生成子。
**dh_Ys**: server的DH公钥(g^X mod p)。

```
struct {
    select (KeyExchangeAlgorithm) {
        case dh_anon:
            ServerDHParams params;
        case dhe_dss:
        case dhe_rsa:
            ServerDHParams params;
            digitally-signed struct {
                opaque client_random[32];
                opaque server_random[32];
                ServerDHParams params;
            } signed_params;
        case rsa:
        case dh_dss:
        case dh_rsa:
            struct {} ;
            /* message is omitted for rsa, dh_dss, and dh_rsa */
        /* may be extended, e.g., for ECDH -- see [TLSECC] */
    };
} ServerKeyExchange;
```

**params**: server的秘钥交换参数。
**signed_params**: 针对非匿名秘钥交换，这是对server的秘钥交换参数的一个签名。

如果client提供了"signature_algorithms"扩展项，签名和hash算法必须使用扩展项中列出的一个。注意这里可能会不一致，举个例子，client可能提供了`DHE_DSS`秘钥交换方法，但在"signature_algorithms"扩展项中忽略了任何DSA算法对。为了正确协商，server在选择加密套件的时候必须先检查该扩展项中的签名算法，防止跟加密套件冲突。这有点儿不那么优雅，但为了让最开始的加密套件协商做尽量小的改变而设计的一个妥协。

另外，hash和签名算法必须跟server的证书中的key相一致。只要证书对秘钥的用法没什么限制，RSA秘钥可以跟任何允许的hash算法相配合。

因为DSA签名不包含对hash算法的任何安全规定，那么在用多个hash算法的时候就可能发生hash算法被替换的风险。现在DSA可以只跟SHA-1配合。将来的DSS版本希望其他摘要算法也能用于DSA，还包括对不同摘要算法使用的秘钥大小作出明确规定。另外，将来的[PKIX]版本可能会明确证书中用于跟DSA配合使用的摘要算法。

最后再强调一下，为TLS设计的包含新秘钥交换算法的加密套件，`ServerKeyExchange`消息只在server证书没有提供足够让client进行秘钥交换的信息的时候才被发送。

### 7.4.4. Certificate Request
该消息发送的时机：如果协商的加密套件合适，非匿名的server可以选择要求client发送它自己的证书。如果发送该消息，需要紧跟着`ServerKeyExchange`消息(如果没发送，就跟着server的`Certificate`消息)。

该消息的结构：
```
enum {
    rsa_sign(1), dss_sign(2), rsa_fixed_dh(3), dss_fixed_dh(4),
    rsa_ephemeral_dh_RESERVED(5), dss_ephemeral_dh_RESERVED(6),
    fortezza_dms_RESERVED(20), (255)
} ClientCertificateType;

opaque DistinguishedName<1..2^16-1>;

struct {
    ClientCertificateType certificate_types<1..2^8-1>;
    SignatureAndHashAlgorithm supported_signature_algorithms<2^16-1>;
    DistinguishedName certificate_authorities<0..2^16-1>;
} CertificateRequest;
```

**certificate_types**: client可能提供证书类型的一个列表。
rsa_sign: 包含RSA秘钥的证书
dss_sign: 包含DSA秘钥的证书
rsa_fixexd_dh: 包含静态DH秘钥的证书
dss_fixed_dh: 包含静态DH秘钥的证书

**supported_signature_algorithms**: server支持的一个hash/签名算法对列表，按优先级排序。
**certificate_authorities**: server接受的一个CA的distinguished names列表[X501]，用DER编码。这些DN可以规定根CA或子CA的DN，因此，该消息可以用于描述已知的根CA和期望的认证域。如果该列表为空，client可以发送任何合适的`ClientCertificateType`，除非还有另外的外部限制。

`certificate_types`和`supported_signature_algorithms`字段之间的相互交互有些复杂，`certificate_types`从SSLv3开始出现，但没被明确定义，它的很多功能都被`supported_signature_algorithms`代替了。原则如下：
- client提供的任何证书都必须用`supported_signature_algorithms`列表中的一个hash/签名算法对来签名。
- client自己的证书必须包含一个跟`certificate_types`相一致的秘钥。如果秘钥是一个签名秘钥，必须能用于`supported_signature_algorithms`中的至少一个hash/签名算法对。
- 因为历史原因，一些client证书类型的名字包含签名此证书的签名算法，比如TLS早期版本中，`rsa_fixed_dh`表示证书中包含一个静态DH秘钥，证书本身使用RSA签名。在TLS1.2Z中，这个功能被`supported_signature_algorithms`淘汰掉了，证书类型名称不再限制签名此证书的签名算法了。例如，如果server发送了`dss_fixed_dh`证书类型和`{{sha1,dsa},{sha1,rsa}}`签名类型，client可以回复一个包含了静态DH秘钥、使用RSA-SHA1签名的证书。

新的`ClientCertificateType`值由IANA添加维护。

注意: 用`RESERVED`列出的值不再用了，它们用于SSLv3。

注意: 一个匿名的server要求client进行认证是个严重的握手错误。

### 7.4.5. Server Hello Done
该消息发送的时机：server发送以表示`ServerHello`和相关信息已经发送完毕了，发送完该消息，server就等着client回复。

该消息的含义：该消息表示server已经发送完了支持秘钥交换的相关信息，client可以开始它的秘钥交换步骤了。

收到该消息后，client应该检查server是否提供了一个合法的证书，检查server的参数是否可接受。

该消息的结构：
```
struct { } ServerHelloDone;
```

### 7.4.6. Client Certificate
该消息发送的时机: 这是client在收到`ServerHelloDone`消息后可以发送的第一个消息。该消息只在server请求client证书的时候才发送。如果没有合适的证书可选择，client必须发送一个不包含证书的消息，也就是说，`certificate_list`结构为空。如果client不发送任何证书，server可以根据自己的判断决定是不要client认证继续握手，还是回复一个`handshake_failure`的严重告警。另外，如果由于证书链的某些方面不合适(比如不是被一个知名CA签发)，server可以决定是继续握手还是发送严重告警中断握手。

client证书消息使用7.4.2节定义的`Certificate`结构体。

该消息的含义: 该消息包含client发送给server的证书链，server会在验证`CertificateVerify`的时候(当client的认证基于签名的时候)或者计算预主密钥的时候(对非瞬时DH算法)。证书必须跟协商的加密套件中的密钥交换算法和任何协商的扩展项相一致。

特别的：
- 证书类型必须是X.509v3，除非另外明确协商。
- 端点证书的公钥(和相应限制)必须跟`CertificateRequest`中列出的证书类型相一致：

| **client证书类型** | **证书公钥类型** |
|-------------------|-----------------|
| rsa_sign          |  RSA公钥；证书必须允许公钥可以在随后的`CertificateVerify`消息中用于签名算法 |
| dss_sign          |  DSA公钥；证书必须允许公钥可以在随后的`CertificateVerify`消息中用于签名算法 |
| ecdsa_sign        |  ECDSA兼容的公钥：证书必须允许公钥可以在随后的`CertificateVerify`消息中用于签名算法；公钥必须使用server支持的曲线和点的格式|
| rsa_fixed_dh, dss_fixed_dh      |  DH公钥；必须用跟server的key一样的参数 |
| rsa_fixed_ecdh, ecdsa_fixed_ecdh|  ECDH兼容公钥；必须用跟server的key一样的曲线，必须用server支持的一个点的格式 |

- 如果`CertificateRequest`消息中的`certificate_authorities`列表不为空，证书链中的至少1个证书必须由列出的CA中的一个签发。
- 证书必须用可接受的hash/signature算法对签名，见[7.4.4.](#7.4.4.)。注意这是对之前TLS版本对证书签名算法限制的一个放宽。

注意，跟server证书一样，有些client证书用的hash/signature算法组合不适用于现在的TLS版本。

### 7.4.7. Client Key Exchange Message
该消息发送的时机：
> client总是会发送该消息。如果发送了client证书，必须紧接着就发送该消息。否则，该消息就是client收到`ServerHelloDone`之后发送的第一个消息。

该消息的含义：
> 预主密钥会在该消息中发送出去，一种方式是用RSA加密后直接发送，另一种是用DH算法，发送DH参数，让client和server能协商出共同的预主密钥。

> 当client用的是瞬时DH参数，该消息会包含client的DH公钥。如果client发送了一个包含静态DH公钥的证书(比如使用`fixed_dh`客户端认证方式)，也必须发送该消息，但该消息为空。

该消息的结构：
> 该消息的结构依赖协商出的密钥交换算法。`KeyExchangeAlgorithm`的定义见[7.4.3.](#7.4.3.)。

```
struct {
    select (KeyExchangeAlgorithm) {
        case rsa:
            EncryptedPreMasterSecret;
        case dhe_dss:
        case dhe_rsa:
        case dh_dss:
        case dh_rsa:
        case dh_anon:
            ClientDiffieHellmanPublic;
    } exchange_keys;
} ClientKeyExchange;
```

#### 7.4.7.1. RSA-Encrypted Premaster Secret Message
该消息的含义：
> 如果密钥协商和认证使用RSA算法，client会生成一个48字节的预主密钥，用server证书中的公钥加密，将加密结果放在`EncryptedPreMasterSecret`中发送给server。该结构是`ClientKeyExchange`的一个字段，不是一个单独的消息。

该消息的结构：
```
struct {
    ProtocolVersion client_version;
    opaque random[46];
} PreMasterSecret;
```

***client_version***: client支持的最新版本，用于检查版本降级攻击。

***random***: 46字节随机数。

```
struct {
    public-key-encrypted PreMasterSecret pre_master_secret;
} EncryptedPreMasterSecret;
```

***pre_master_secret***: client生成的随机数，用于生成主密钥，见[8.1.](#8.1.1);

注意: ``PreMasterSecret`是celint在`ClientHello.client_version`中提供的版本号，不是该连接协商出。设计该特性是用于抵抗版本降级攻击。但不好的是，一些旧的实现使用了协商出的版本号，因此检查该值是否设置正确可能会导致握手失败。

符合本文档的client实现**必须**总是在`PreMasterSecret`中发送正确的版本号。如果`ClientHello.client_version`是TLS1.1或更高，server**必须**按照如下规则检查该版本号。如果该版本号是TLS1.0或更低，server**应该**检查该值，但**可以**有一个开关关闭该检查。注意如果检查失败，`PreMasterSecret`的值**应该**按照如下描述进行随机化。

注意: 由Bleichenbacher[BLEI]和Klima et al.[KPR03]发现的攻击方法可以攻击TLS server，以发现一个特定消息在被解密时，是否正确用PKCS#1格式构建，是否包含一个正确的`PreMasterSecret`结构体，或者是否有正确的版本号。

如Klima[KPR03]所述，可以通过区别对待没有正确构建和/或版本号不匹配的结构体与正确构建的结构体，来避免这些脆弱点。换句话说就是：
1. 生成一个46字节的随机串R
2. 解密该消息以恢复明文M
3.
```
if PKCS#1填充不正确，or 消息M的长度不是正好的48字节：
    pre_master_secret = ClientHello.client_version || R
else if ClientHello.client_version <= TLS 1.0, and 明确关闭了版本号检查功能:
    pre_master_secret = M
else
    pre_master_secret = ClientHello.client_version || M[2..47]
```

注意，如果client在原始的`pre_master_secret`中使用了错误的版本号，那么用`ClientHello.client_version`明确构建的`pre_master_secret`会生成一个非法的`master_secret`。

一个可选的解决办法是将版本号不匹配当成PKCS#1格式错误，完全将预主密钥随机化：
1. 生成一个48字节的随机串R
2. 解密该消息以恢复明文M
3.
```
if PKCS#1填充不正确， or 消息M的长度不是正好的48字节:
    pre_master_secret = R
else if ClientHello.client_version <= TLS 1.0, and 明确关闭了版本号检查功能：
    pre_master_secret = M
else if M[0..1] != ClientHello.client_version:
    pre_masetr_secret = R
else:
    pre_master_secret = M
```

尽管还没见过实际针对这种构建方法的攻击，但Klima et al.[KPR03]描述了理论上的攻击手段，因此建议使用第一种方法。

不管哪种情况，TLS server在处理RSA加密的预主密钥失败的时候都**不准**发送告警，或者生成不是期望的版本号的告警，而是使用一个随机生成的预主密钥继续握手。可以记录下实际导致握手失败的原因；但必须注意不能泄露信息给攻击者(比如从时间，日志文件，或者其他信道)。

在[PKCS1]中定义的RSAES-OAEP加密模式对抵御Bleichenbacher攻击更有效。但是，为了跟之前的TLS版本最大程度的兼容，本规定使用RSAES-PKCS1-v1_5加密模式。如果按照之前的建议去实现，还没发现有什么Bleichenbacher攻击的变种被发现。

实现细节：公钥加密的数据用一个未定义的向量<0..2^16-1>来表示(见[4.7.](#4.7.))。因此，在`ClientKeyExchange`消息中被RSA加密的`PreMasterSecret`前边有2字节的长度。这2个字节在RSA的情况下是多余的，因为`EncryptedPreMasterSecret`是`ClientKeyExchange`中唯一的数据，并且长度可以被明确定义。SSLv3的规定中里没有明确公钥加密数据的编码格式，因此很多SSLv3的实现就没有包含这2个长度字段——它们直接在`ClientKeyExchange`消息中编码了RSA加密后的数据。

本规定要求必须完整包含长度字段。结果就是数据单元跟很多SSLv3的实现不兼容。基于SSLv3进行升级的实现者**必须**调整从他们的实现代码以生成和接受正确的编码。实现者想同时兼容SSLv3和TLS的话，需要根据协议版本去选择合适的编解码过程。

实现细节：现在我们都知道远程基于时间的攻击是可能的，至少client和server在同一个局域网是可以的。所以使用静态RSA密钥的实现者**必须**使用RSA blinding或者其他抵抗时间攻击的技术，见[TIMING](#TIMING)。

#### 7.4.7.2 Client Diffie-Hellman Public Value
该消息的含义：
> 如果没有在client证书包含，该消息会携带client的DH的公钥(Yc)。Yc的编码格式由枚举值`PublicValueEncoding`决定。该结构是`ClientKeyExchange`的一个字段，不是一个单独的消息。

该消息的结构：
```
enum { implicit, explicit } PublicValueEncoding;
```

***implicit***: 如果client发送的证书包含有合适的DH公钥(对于`fixed_dh`client认证方式)，那么Yc就是隐含的，并且不会再被发送一次。这种情况等下，也会发送`ClientKeyExchange`消息，但该消息为空。

***explicit***: Yc需要被发送。

```
struct {
    select (PublicValueEncoding) {
        case implicit: struct { };
        case explicit: opaque dh_Yc<1..2^16-1>;
    } dh_public;
} ClientDiffieHellmanPublic;
```

***dh_Yc***: client的DH公钥(Yc)。

### 7.4.8. Certificate Verify
该消息发送的时机：
> 该消息用于给client证书提供明确证明。该消息只会在client发送了一个可以用于签名的证书(除包含静态DH公钥的其他所有证书)之后发送。如果发送，**必须**紧接着`ClientKeyExchange`消息。

该消息的结构：
```
struct {
    digitally-signed struct {
        opaque handshake_messages[handshake_messages_length];
    }
} CertificateVerify;
```

这里`handshake_messages`表示所有发送和接收到的握手消息，从`ClientHello`一直到该消息，但不包含该消息。所有消息都拼接在一起([7.4](#7.4)定义的)。注意这要求两端都缓存所有消息或者用所有可能的hash算法计算hash值，直到计算`CertificateVerify`消息为止。server可以在`CertificateRequest`消息中限制一组摘要算法以减少计算量。

这里签名使用的hash/signature算法对**必须**是`CertificateRequest`消息中`supported_signature_algorithms`列表中的一个。另外，hash和signature算法对**必须**跟client本身的证书中的公钥相匹配。除了证书中有特殊限制，RSA公钥**可以**跟任何允许的hash算法配合。

因为DSA签名不包含任何对hash算法的安全性规定，如果一个密钥可以跟多个hash算法配合使用的话，会有hash算法被替换的风险。当前的DSA[DSS]算法可以只跟SHA-1配合，将来的DSS[DSS-3]版本期望可以使用其他摘要算法，也会规定每种大小的密钥使用哪种摘要算法。另外，将来的[PKIX]修订版可能会在证书中添加机制来指导DSA使用哪种签名算法。

### 7.4.9. Finished
该消息发送的时机：
> 总是随着`ChangeCipherSpec`消息发送，以验证密钥交换和认证成功了。必须在其他握手消息和`Finished`消息之间收到一个`ChangeCipherSpec`消息才行。

该消息的含义：
> 该消息是第一个用协商出的算法、密钥、加密参数保护的数据。接收者必须校验消息内容是否正确。一旦一端发送了`Finished`，并且收到并校验的对端的`Finished`消息，就可以发送和接收应用数据了。

该消息的结构：
```
struct {
    opaque verify_data[verify_data_length];
} Finished;
```

***verify_data***: PRF(master_secret, finished_label, Hash(handshake_messages))[0..verify_data_length-1];

***finished_label***: 对client发送的该消息，该字符串是"client finished"。对server发送的该消息，该字符串是"server finished"。

`Hash`表示对握手消息的一个hash的算法。对[5](#5)节定义PRF算法，`Hash`**必须**是用于PRF的`Hash`。任何定义一个不同PRF算法的加密套件，都必须同时定义`Finished`消息计算时候的`Hash`。

在之前的TLS版本中，`verify_data`总是12字节。在当前TLS版本中，它的长度依赖加密套件。加密套件没有明确规定`verify_dat_length`的话，就默认是12字节，现有的加密套件都是12字节。注意本规定中的编码方式跟之前的协议版本规定的一样。将来的加密套件**可能**规定其他长度，但最短**必须**12字节。

***handshake_messages***: 包含到现在为止的所有握手消息(不包含任何`HelloRequest`消息)，但不包含本消息。这些只是握手层可见的数据，不包含记录层的头，所有消息都是拼接在一起的。

如果`Finished`消息之前不是`ChangeCipherSpec`，就是个严重错误。

`handshake_messages`的值包含从`ClientHello`开始到现在的所有握手消息，但不包含`Finished`消息本身。这跟[7.4.8](#7.4.8)节中的`handshake_messages`不一样，因为这里的会包含`CertificateVerify`消息(如果发送了的话)。并且，client发送的`Finished`消息中的`handshake_messages`跟server发送的也不一样，因为后发送的会包含前一个发送的。

注意：`ChangeCipherSpec`消息、告警和其他不是握手消息的记录层消息类型不用于hash计算。并且，也要忽略掉`HelloRequest`消息。

# 8. 密钥计算
为了开始连接保护，TLS记录层协议需要一套加密算法、一个主秘钥和client、server的随机数。认证、加密、MAC算法由server选出`cipher_suite`决定，并在`ServerHello`中体现。压缩算法在hello消息中协商，随机数也在hello消息中交换。接下来就剩下计算主秘钥了。

## 8.1. 计算主秘钥
不管什么秘钥交换算法，将`pre_master_secret`转换成`master_secret`都用的是同一个算法。一旦`master_secret`计算完成，就要将`pre_master_secret`从内存中删除掉。
```
master_secret = PRF(pre_master_secret, "master secret", ClientHello.random + ServerHello.random)[0..47];
```

`master_secret`总是48字节，`pre_master_secret`则会随着秘钥交换算法不同而改变。

### 8.1.1. RSA
当用RSA进行server认证和秘钥交换时，client会生成一个48字节的`pre_master_secret`，用server的公钥加密，然后发送给server。server使用它自己的私钥解密出`pre_master_secret`。然后两端按照上边说的方法将`pre_master_secret`转换成`master_secret`。

### 8.1.2. Diffie-Hellman
DH算法的计算就很简单了。协商出的秘钥(Z)被用作`pre_master_secret`，然后被转换成`master_secret`。Z的前导0位在用作`pre_master_secret`的时候都要删掉。

注意： DH的参数由server规定，并且可能是临时生成的或者在server的证书中固定保存的。

# 9. 必须要实现的加密套件














# 附录E：后向兼容性
## E.1. 跟TLS 1.0/1.1 和SSL 3.0的兼容性


<a id="TIMING"/>[TIMING]</a> Boneh, D., Brumley, D., "Remote timing attacks are
practical", USENIX Security Symposium 2003.