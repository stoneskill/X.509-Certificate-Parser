#pragma once
#include <cstdio>
#include <map>
#include <string>
#include <vector>
using std::map;
using std::string;
using std::vector;

struct TLV {
    unsigned char tag;
    int length;
    int offset;
    vector<unsigned char> value;
    TLV() {}
    TLV(const vector<unsigned char> &v) {
        offset = 2;
        tag = v[0];
        this->length = 0;
        if (v[1] & 0x80 != 0) {
            offset += v[1] & 0x7f;
            for (int i = 2; i < offset; i++) {
                this->length <<= 8;
                this->length += v[i];
            }
        } else {
            this->length = v[1];
        }

        for (int j = offset; j < offset + this->length; j++) {
            this->value.push_back(v[j]);
        }
    }

    void print() {
        printf("tag: %u\n", this->tag);
        printf("length: %d\n", this->length);
        printf("value: ");
        for (int i = 0; i < this->value.size(); i++) {
            printf("%u", this->value[i]);
        }
        printf("\n");
    }
};

struct Field {
    unsigned char tag;
    string valueStr;
    vector<unsigned char> valueVec;
    Field() {}
    Field(unsigned char n, const string &v) : tag(n), valueStr(v) {}
    Field(unsigned char n, const vector<unsigned char> &v)
        : tag(n), valueVec(v) {}
};

const unsigned char BOOLEAN = 0X1, INTEGER = 0X2, BITSTRING = 0X3,
                    OCTETSTRING = 0X4, OBJECT = 0X6, SEQUENCE = 0X10,
                    SET = 0X11, PRINTABLE = 0X13, IA5STRING = 0X16,
                    UTCTIME = 0X17, VERSION = 0xA0, STRUCTURE = 0X30,
                    SET = 0X31, EXTENSION = 0XA3;

const string BOOLEAN_STR = "Boolean", INTEGER_STR = "Integer",
             BITSTRING_STR = "Bit string", OCTETSTRING_STR = "Octet string",
             OBJECT_STR = "Object", SEQUENCE_STR = "Sequence", SET_STR = "Set",
             PRINTABLE_STR = "Printable", IA5STRING_STR = "IA5String",
             UTCTIME_STR = "UTCTime", VERSION_STR = "Version",
             STRUCTURE_STR = "Structure";

map<string, string> mapping = {
    {"1.3.6.1.5.5.7.3.1", "服务器身份验证(id_kp_serverAuth): True"},
    {"1.3.6.1.5.5.7.3.2", "客户端身份验证(id_kp_clientAuth): True"},
    {"2.5.29.37", "扩展密钥用法(Extended key usage):"},
    {"2.5.29.31", "CRL Distribution Points:"},
    {"1.2.840.10045.2.1", "EC Public Key:"},
    {"2.23.140.1.2.2", "组织验证(organization-validated):"},
    {"1.3.6.1.5.5.7.1.1", "AuthorityInfoAccess:"},
    {"2.5.29.19", "基本约束(Basic Constraints):"},
    {"1.3.6.1.5.5.7.3.2", "客户端身份验证(id_kp_clientAuth): True"},
    {"1.2.840.10045.3.1.7",
     "推荐椭圆曲线域(SEC 2 recommended elliptic curve domain): \n"},
    {"2.5.29.35", "授权密钥标识符(Authority Key Identifier): "},
    {"2.5.29.14", "主体密钥标识符(Subject Key Identifier): "},
    {"1.3.6.1.5.5.7.2.1", "OID for CPS qualifier: "},
    {"1.3.6.1.5.5.7.48.1", "OCSP: "},
    {"1.3.6.1.5.5.7.48.2", "id-ad-caIssuers: "},
    {"1.3.6.1.4.1.311.60.2.1.1", "所在地(Locality): "},
    {"1.3.6.1.4.1.311.60.2.1.3", "国家(Country): "},
    {"1.3.6.1.4.1.311.60.2.1.2", "州或省(State or province): "},
    {"2.5.4.3", "通用名称(common name): "},
    {"2.5.4.5", "颁发者序列号(serial number): "},
    {"2.5.4.6", "颁发者国家名(country name): "},
    {"2.5.4.7", "颁发者位置名(locality name): "},
    {"2.5.4.8", "颁发者州省名(stateOrProvince name): "},
    {"2.5.4.9", "颁发者街区地址(streetAddress): "},
    {"2.5.4.10", "颁发者组织名(organization name): "},
    {"2.5.4.11", "颁发者组织单位名(organizational unit name): "},
    {"2.5.4.12", "颁发者标题(title): "},
    {"2.5.4.13", "颁发者描述(description): "},
    {"2.5.4.15", "颁发者业务类别(businessCategory): "},
    {"2.5.29.32", "证书策略(Certificate Policies): "},
    {"2.5.29.15", "使用密钥(Key Usage): "},
    {"1.2.840.10040.4.1", "DSA"},
    {"1.2.840.10040.4.3", "sha1DSA"},
    {"1.2.840.113549.1.1.1", "RSA"},
    {"1.2.840.113549.1.1.2", "md2RSA"},
    {"1.2.840.113549.1.1.3", "md4RSA"},
    {"1.2.840.113549.1.1.4", "md5RSA"},
    {"1.2.840.113549.1.1.5", "sha1RSA"},
    {"1.3.14.3.2.29", "sha1RSA"},
    {"1.2.840.113549.1.1.13", "sha512RSA"},
    {"1.2.840.113549.1.1.11", "sha256RSA"}};

struct Certificate {
    vector<Field> tokens;
    Certificate() {}
    ~Certificate() {}
    void printCertificate() {
        for (int i = 0; i < tokens.size(); i++) {
            if (tokens[i].tag == VERSION){}
        }
    }
};