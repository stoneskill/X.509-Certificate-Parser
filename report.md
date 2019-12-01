# X.509 数字证书解析

16327109 谢昆成

## 实验要求

设计并实现一个小程序，读入一个X.509 数字证书，按照标准定义给出证书中有关项目的中(英)文内容陈述。

## X.509 证书总体结构

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

解释如下：

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

   证书有效期的时间段。由”Not Before”和”Not After”两项组成，它们分别由UTC时间或一般的时间表示。
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



### Base64

从网络上下载的证书一般是base64编码，需要进行解码。

Base64是一种用64个字符来表示任意二进制数据的方法。

编码方式： 对二进制数据进行处理，每3个字节一组，一共是`3x8=24`bit，划为4组，每组正好6个bit。 以以下64个字符分别对应`0,1,2,...63`来表示这6个bit。

```
['A', 'B', 'C', ... 'a', 'b', 'c', ... '0', '1', ... '+', '/']
```

解码即编码的逆过程，将以上字符分别转换为表示0-63的字节，再将其拼接。

### TLV

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

object identifier 是对象标识符，由国际电信联盟(ITU)和ISO/IEC标准化的标识符机制，用于表示对一个对象、概念或者事务的全球化的一种标识。形式是$v_1.v_2...v_n$，如`1.3.6.1`表示Internet。

object identifier的第一个字节为$v_1*40+v_2$，由此计算出$v_1$和$v_2$。从$v_3$开始的字符计算方法：如果字节最高位为1，则说明当前字节并非$v_i$的最后一个字节，需要和后续字节一起组成$v_i$；如果最高位为0，说明当前字节为这个$v_i$的最后一个字节。

- Length

Value区的大小（以字节为单位），小段存储。

分为长length和短length，如果第8位是1，则为长length，存储长度信息所占用的字节；否则，此字节即为数据区的长度。

- Value

数据区，长度可变的字节集。

## 数据结构

首先，我们用`TLV`数据结构来解析证书

```cpp
struct TLV {
    unsigned char tag;
    int length;
    int offset;
    vector<unsigned char> value;
    TLV() {}
    TLV(const vector<unsigned char> &v, int begin) {
        offset = 2;
        tag = v[begin];
        this->length = 0;
        if ((v[begin + 1] & 0x80) != 0) {
            offset += v[begin + 1] & 0x7f;
            for (int i = begin + 2; i < begin + offset; i++) {
                this->length <<= 8;
                this->length += v[i];
            }
        } else {
            this->length = v[begin + 1];
        }

        for (int j = begin + offset;
             j < v.size() && j < begin + offset + this->length; j++) {
            this->value.push_back(v[j]);
        }
    }
};
```



用`Field`表示证书中的字段

```cpp
struct Field {
    unsigned char tag;
    string valueStr;
    vector<unsigned char> valueVec;
    Field() {}
    Field(unsigned char n, const string &v) : tag(n), valueStr(v) {}
    Field(unsigned char n, const vector<unsigned char> &v)
        : tag(n), valueVec(v) {}
};
```

`Field`中可存放string类型和数据和vector\<unsigned char\>类型的数据。



依照X.506证书的结构，定义一个数据结构存放tokens表示证书。

```cpp
struct Certificate {
  private:
    Field token;
    int cur;

    void printVec(const vector<unsigned char> &v) {
        for (int i = 0; i < v.size(); i++) {
            printf("%02x", v[i]);
        }
        printf("\n");
    }

    void printTime(const string &time) {
        printf("20%c%c year, %c%c month, %c%c day, %c%c:%c%c:%c%c \n", time[0],
               time[1], time[2], time[3], time[4], time[5], time[6], time[7],
               time[8], time[9], time[10], time[11]);
    }

  public:
    vector<Field> tokens;
    Certificate() { cur = 0; }
    ~Certificate() {}

    void printCertificate() {
      // ...
    }
}
```



## 编译运行方法

- 编译方法

进入src目录，运行

```bash
g++ main.cpp -o main -std=c++11
```

- 运行方法

```bash
main 文件名
```

例如百度的证书baidu_com.crt

```bash
 main ..\examples\baidu_com.crt
```



## 实验结果

对百度的证书[baidu_com.crt](./examples/baidu_com.crt)进行解析

```
Version: 3
Sequence: 2cee193c188278ea3e437573
Algorithm: sha256RSA
country name:
  BE
organization name:
  GlobalSign nv-sa
common name:
  GlobalSign Organization Validation CA - SHA256 - G2
Validity:
  not before: 2019 year, 05 month, 09 day, 01:22:02
  not after: 2020 year, 06 month, 25 day, 05:31:02
country name:
  CN
stateOrProvince name:
  beijing
locality name:
  beijing
organizational unit name:
  service operation department
organization name:
  Beijing Baidu Netcom Science Technology Co., Ltd
common name:
  baidu.com
Algorithm: RSA
Bit string: 003082010a0282010100b4c6bfda53200fea40f3b85217663b36018d12b4990dd39b6c1853b11908b0fa73473e0d3a796278612e543c497c56dac0be6155d542706a10bef5bd8d6496210093630987b719ba0e203e49c853ed028f4601eba1079373bbedf1b3c9e2fbddf0392a83adf44198bc86eaba74a8a6e3d0e5c58eb30bb2d2ac91740eff80102336626508b487f5570c25c700d8f5a85db83341a72a5fdbfa709e21bbae4216660769fe1c262a810fab73e3d65220a46da86cd46648a46ff2680ac565a14ebf047a40431cd375fb75ac19d64a35056ecfd565d144ca6b0c5804c4854f1fbe2c32d1f1c628fbf92636b56dfacb96a2a0d0bcf851df0744bd8f6f67c0d4afd9cdc30203010001
Key Usage:
  TRUE
Bit string: 05a0
AuthorityInfoAccess:
id-ad-caIssuers:
  http://secure.globalsign.com/cacert/gsorganizationvalsha2g2r1.crt
OCSP:
  http://ocsp2.globalsign.com/gsorganizationvalsha2g2
Certificate Policies:
  1.3.6.1.4.1.4146.1.20
OID for CPS qualifier:
  https://www.globalsign.com/repository/
organization-validated:
Basic Constraints:
CRL Distribution Points:
Version: 135
Sequence:
owner:
  baidu.com
  click.hm.baidu.com
  cm.pos.baidu.com
  log.hm.baidu.com
  update.pan.baidu.com
  wn.pos.baidu.com
  *.91.com
  *.aipage.cn
  *.aipage.com
  *.apollo.auto
  *.baidu.com
  *.baidubce.com
  *.baiducontent.com
  *.baidupcs.com
  *.baidustatic.com
  *.baifae.com
  *.baifubao.com
  *.bce.baidu.com
  *.bcehost.com
  *.bdimg.com
  *.bdstatic.com
  *.bdtjrcv.com
  *.bj.baidubce.com
  *.chuanke.com
  *.dlnel.com
  *.dlnel.org
  *.dueros.baidu.com
  *.eyun.baidu.com
  *.fanyi.baidu.com
  *.gz.baidubce.com
  *.hao123.baidu.com
  *.hao123.com
  *.hao222.com
  *.im.baidu.com
  *.map.baidu.com
  *.mbd.baidu.com
  *.mipcdn.com
  *.news.baidu.com
  *.nuomi.com
  *.safe.baidu.com
  *.smartapps.cn
  *.ssl2.duapps.com
  *.su.baidu.com
  *.trustgo.com
  *.xueshu.baidu.com
  apollo.auto
  baifae.com
  baifubao.com
  dwz.cn
  mct.y.nuomi.com
  www.baidu.cn
  www.baidu.com.cn
Extended key usage:
id_kp_serverAuth: True
id_kp_clientAuth: True
Subject Key Identifier:
Authority Key Identifier:
  96de61f1bd1c1629531cc0cc7d3b830040e61a7c
Algorithm: sha256RSA
Signature value: 00aab9cd528edc365d47d48bf3321706468360a327054929b11b466e38fe93fe09436cd2a158241242b7ab41f8470a7d64b575dc5a4514b2a4186b9cb73b8fb37ed2bdc0724b3505ae0d2d191f5073725adf97183bdb2af3de44ce642dc11e84cc76243e30672326e84ff70bf6ec69d77f51a9a06fb8c414e2c04a4ac4005d576ac941c4252b3218aa62a81e4981731c815f5efae49432c3506d8eaacc6c4c530cfa8f4e34799fa560c0f85075b8a19d01e6ab25230c3b2402405824ff34028b946110682fb680e3d05f4a0aa702d2c0983e1de802c8277126b2a887b6db9d10474bc2136234c6d03c390939258ffea2f4f3fbdf9b273dfcd028e86ddcdd17d31f
```



对中山大学的证书[-_sysu_edu_cn.crt](./examples/-_sysu_edu_cn.crt)进行解析

```
Version: 3
Sequence: 1d4ed049f188fb4a94d8a8ee2d757915
Algorithm: sha256RSA
country name:
  CN
organization name:
  2.5.4.3
Validity:
  not before: 2018 year, 05 month, 16 day, 17:44:14
  not after: 2020 year, 07 month, 13 day, 17:44:14
country name:
  CN
organization name:
  2.5.4.7
stateOrProvince name:
  2.5.4.3
Algorithm: RSA
Bit string: 003082010a0282010100d7c2bfd57b0eaea06944b7b2583ca1cea39dad163cb01b864ca67844ec23792697ee41f304cf7ebb2f604557c0572588ee630d49e7a65e08fe2aaf1b59d81dad54afef5050c81234983110a3b6d345b042b2ef882a3cc26b5a025c56181610fb27f53120037b7729c91eed8ff7a4727f9d5dd9a186eeeddd595f560f3ca484d88237c0c6afe56767d247c24db6e92f6234693ee98fa615d907a338dc58f413fffad664f26f9bac1ae577cd994b7fa4a420bef038056eb99a25bd65825307837810e29658fc2b046aa46c5e14ce5e35a7417b4467a316b4a10474bfcb0f43f622b8f4f85fc563885efb3b9bd0ea37cfb0fd213bfc1d1a8cad4621557b191e11490203010001
Basic Constraints:
Boolean:  TRUE
CRL Distribution Points:
Version: 135
Sequence:
AuthorityInfoAccess:
OCSP:
  http://wotrus-ovca.ocsp-certum.com
id-ad-caIssuers:
  http://repository.certum.pl/wotrus-ovca.cer
Authority Key Identifier:
  6ac04919529fea015e450cb1f00f7ea05f6d8fe5
Subject Key Identifier:
Certificate Policies:
  2.23.140.1.2.2
OID for CPS qualifier:
  https://www.certum.pl/CPS
Extended key usage:
id_kp_serverAuth: True
id_kp_clientAuth: True
Key Usage:
  TRUE
Bit string: 05a0
owner:
  *.sysu.edu.cn
  sysu.edu.cn
Boolean:  FALSE
Algorithm: sha256RSA
Bit string: 000e7351e1de7af692f44a2105ea30347655983a620d7afd38f59876b78d1fcd83a9c9ef0d3d10e733e3d0ea0f4628a5134873405b90e2d654d70b15c9adb84be361b0ade4814770c8d7e0b8cd85730ce60409c3c1fd93cc44a65455ce3bd251fe4fdd2e78afbab7402305f270aaf9f35033a3f0c2e8532de0348b2817bdc45988709859a0a80492cfabdf3bf7ea69f5e9966706597045fa676c29fde1520659ed460f18b19f0d2142f98a4466178d5baa2e557bbba6d26c13bb928be6c2d0cdd3df8dc8e857698258eb870cac19ed193f58d0e426fedf7f80a8be405e3a3b0f7f39e7ffa65f611541e5e3aace0ad85836213d38a451811597d39df241cd341214
```



## 源代码

主函数[main.cpp](./src/main.cpp)

证书数据结构[certificate.h](./src/certificate.h)

证书解析程序[x509.h](./src/x509.h)



## 实验体会

通过这次实验，深入了解了x.509证书的数据结构和解析方法。X.509证书解析，实则如同编译原理的语法分析。ASN.1编码方式比较独特，类型较多，解析起来比较复杂。

## 参考文献

- [RFC 5280 Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile](https://datatracker.ietf.org/doc/rfc5280/)
- [ASN.1]()