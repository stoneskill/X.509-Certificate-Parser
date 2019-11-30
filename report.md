# X.509 数字证书解析

16327109 谢昆成

## 实验要求

设计并实现一个小程序，读入一个X.509 数字证书，按照标准定义给出证书中有关项目的中(英)文内容陈述。

## X.509 证书

X.509 是密码学里公钥证书的格式标准。

由RFC5280文档可知X.509 v3证书结构如下：

```
   Certificate  ::=  SEQUENCE  {
        tbsCertificate       TBSCertificate,
        signatureAlgorithm   AlgorithmIdentifier,
        signatureValue       BIT STRING  }

   TBSCertificate  ::=  SEQUENCE  {
        version         [0]  EXPLICIT Version DEFAULT v1,
        serialNumber         CertificateSerialNumber,
        signature            AlgorithmIdentifier,
        issuer               Name,
        validity             Validity,
        subject              Name,
        subjectPublicKeyInfo SubjectPublicKeyInfo,
        issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
                             -- If present, version MUST be v2 or v3
        subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
                             -- If present, version MUST be v2 or v3
        extensions      [3]  EXPLICIT Extensions OPTIONAL
                             -- If present, version MUST be v3
        }

   Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }

   CertificateSerialNumber  ::=  INTEGER

   Validity ::= SEQUENCE {
        notBefore      Time,
        notAfter       Time }

   Time ::= CHOICE {
        utcTime        UTCTime,
        generalTime    GeneralizedTime }

   UniqueIdentifier  ::=  BIT STRING

   SubjectPublicKeyInfo  ::=  SEQUENCE  {
        algorithm            AlgorithmIdentifier,
        subjectPublicKey     BIT STRING  }

   Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension

   Extension  ::=  SEQUENCE  {
        extnID      OBJECT IDENTIFIER,
        critical    BOOLEAN DEFAULT FALSE,
        extnValue   OCTET STRING
                    -- contains the DER encoding of an ASN.1 value
                    -- corresponding to the extension type identified
                    -- by extnID
        }
```

中文解释如下：

### tbsCertificate

1. X.509证书基本部分
   1.1. 版本号.

   标识证书的版本（版本1、版本2或是版本3）。
   1.2. 序列号

   标识证书的唯一整数，由证书颁发者分配的本证书的唯一标识符。
   1.3. 证书签名算法

   用于签证书的算法标识，由对象标识符加上相关的参数组成，用于说明本证书所用的数字签名算法。例如，SHA-1和RSA的对象标识符就用来说明该数字签名是利用RSA对SHA-1杂凑加密。
   1.4. 颁发者

   证书颁发者的可识别名（DN）。
   1.5. 有效期

   证书有效期的时间段。本字段由”Not Before”和”Not After”两项组成，它们分别由UTC时间或一般的时间表示（在RFC2459中有详细的时间表示规则）。
   1.6. 持有者

   证书拥有者的可识别名，这个字段必须是非空的，除非你在证书扩展中有别名。
   1.7. 持有者公钥信息

   持有者的公钥（以及算法标识符）。
   1.8. 颁发者唯一标识符

   标识符—证书颁发者的唯一标识符，仅在版本2和版本3中有要求，属于可选项。
   1.9. 持有者唯一标识符

   证书拥有者的唯一标识符，仅在版本2和版本3中有要求，属于可选项。

2. X.509证书扩展部分

   可选的标准和专用的扩展（仅在版本2和版本3中使用），扩展部分的元素都有这样的结构：
   
   ```
   Extension ::= SEQUENCE {
     extnID      OBJECT IDENTIFIER,
     critical    BOOLEAN DEFAULT FALSE,    
     extnValue   OCTET STRING 
   }
   ```
   
   extnID：表示一个扩展元素的OID
   
   critical：表示这个扩展元素是否重要
   
   extnValue：表示这个扩展元素的值，字符串类型。
   
   扩展部分包括：
   2.1. 发行者密钥标识符
   
   证书所含密钥的唯一标识符，用来区分同一证书拥有者的多对密钥。
   2.2. 密钥使用
   
   一个比特串，指明（限定）证书的公钥可以完成的功能或服务，如：证书签名、数据加密等。
   
   如果某一证书将 KeyUsage 扩展标记为“极重要”，而且设置为“keyCertSign”，则在 SSL 通信期间该证书出现时将被拒绝，因为该证书扩展表示相关私钥应只用于签写证书，而不应该用于 SSL。
   2.3. CRL分布点
   
   指明CRL的分布地点。
   2.4. 私钥的使用期
   
   指明证书中与公钥相联系的私钥的使用期限，它也有Not Before和Not After组成。若此项不存在时，公私钥的使用期是一样的。
   2.5. 证书策略
   
   由对象标识符和限定符组成，这些对象标识符说明证书的颁发和使用策略有关。
   2.6. 策略映射
   
   表明两个CA域之间的一个或多个策略对象标识符的等价关系，仅在CA证书里存在。
   2.7. 主体别名
   
   指出证书拥有者的别名，如电子邮件地址、IP地址等，别名是和DN绑定在一起的。
   2.8. 颁发者别名
   
   指出证书颁发者的别名，如电子邮件地址、IP地址等，但颁发者的DN必须出现在证书的颁发者字段。
   2.9. 主体目录属性
   
   指出证书拥有者的一系列属性。可以使用这一项来传递访问控制信息。
   
   
   

### algorithmIdentifier

   1. 证书签名算法

   用于说明本证书所用的数字签名算法。

### signatureValue

1. 证书签名值

   证书的签名



X.509证书采用TLV（tag-length-value）格式存储，为ANS.1跨平台的编码格式的一种。

- Tag

用一个数字代码表示整个数据块的类型。具体如下表

| Type                         | Tag number (decimal) | Tag number (hexadecimal) |
| ---------------------------- | -------------------- | ------------------------ |
| `INTEGER`                    | 2                    | `02`                     |
| `BIT STRING`                 | 3                    | `03`                     |
| `OCTET STRING`               | 4                    | `04`                     |
| `NULL`                       | 5                    | `05`                     |
| `OBJECT IDENTIFIER`          | 6                    | `06`                     |
| `SEQUENCE` and `SEQUENCE OF` | 16                   | `10`                     |
| `SET` and `SET OF`           | 17                   | `11`                     |
| `PrintableString`            | 19                   | `13`                     |
| `T61String`                  | 20                   | `14`                     |
| `IA5String`                  | 22                   | `16`                     |
| `UTCTime`                    | 23                   | `17`                     |

- Length

Value区的大小（以字节为单位），小段存储。

分为长length和短length，如果第8位是1，则为长length，存储长度信息所占用的字节；否则，此字节即为数据区的长度。

- Value

数据区，长度可变的字节集。

## 数据结构

依照X.506证书的结构，我们可以定义一个类似的数据结构。



## 编译运行方法



## 源代码



## 实验体会