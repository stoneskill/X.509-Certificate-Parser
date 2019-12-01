#pragma once
#include <iostream>
#include <map>
#include <string>
#include <vector>
using std::cout;
using std::endl;
using std::map;
using std::string;
using std::vector;

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

const unsigned char PUBLICKEY = 0X0, BOOLEAN = 0X1, INTEGER = 0X2,
                    BITSTRING = 0X3, OCTETSTRING = 0X4, NUL = 0x5, OBJECT = 0X6,
                    SEQUENCE = 0X10, SET = 0X31, PRINTABLE = 0X13,
                    IA5STRING = 0X16, SPEIA5STRING = 0X86, SUBJECTID = 0X82,
                    UTCTIME = 0X17, VERSION = 0xA0, STRUCTURE = 0X30,
                    EXTENSION = 0XA3, OUTPUT = 0X80;

const string PUBLICKEY_STR = "Public key", BOOLEAN_STR = "Boolean",
             INTEGER_STR = "Integer", BITSTRING_STR = "Bit string",
             OCTETSTRING_STR = "Octet string", NUL_STR = "Null",
             OBJECT_STR = "Object", SEQUENCE_STR = "Sequence", SET_STR = "Set",
             PRINTABLE_STR = "Printable", IA5STRING_STR = "IA5String",
             SPEIA5STRING_STR = "Special IA5String",
             SUBJECTID_STR = "Subject id", UTCTIME_STR = "UTCTime",
             VERSION_STR = "Version", STRUCTURE_STR = "Structure",
             EXTENSION_STR = "Extension", OUTPUT_STR = "Output";

map<unsigned char, string> tagName = {{PUBLICKEY, PUBLICKEY_STR},
                                      {BOOLEAN, BOOLEAN_STR},
                                      {INTEGER, INTEGER_STR},
                                      {BITSTRING, BITSTRING_STR},
                                      {OCTETSTRING, OCTETSTRING_STR},
                                      {NUL, NUL_STR},
                                      {OBJECT, OBJECT_STR},
                                      {SUBJECTID, SUBJECTID_STR},
                                      {SEQUENCE, SEQUENCE_STR},
                                      {SET, SET_STR},
                                      {PRINTABLE, PRINTABLE_STR},
                                      {IA5STRING, IA5STRING_STR},
                                      {SPEIA5STRING, SPEIA5STRING_STR},
                                      {UTCTIME, UTCTIME_STR},
                                      {VERSION, VERSION_STR},
                                      {STRUCTURE, STRUCTURE_STR},
                                      {EXTENSION, EXTENSION_STR},
                                      {OUTPUT, OUTPUT_STR}};

map<string, string> mapping1 = {
    {"1.3.6.1.5.5.7.3.1", "id_kp_serverAuth: True"},
    {"1.3.6.1.5.5.7.3.2", "id_kp_clientAuth: True"},
    {"2.5.29.37", "Extended key usage:"},
    {"2.5.29.31", "CRL Distribution Points:"},
    {"1.2.840.10045.2.1", "EC Public Key:"},
    {"2.23.140.1.2.2", "organization-validated:"},
    {"1.3.6.1.5.5.7.1.1", "AuthorityInfoAccess:"},
    {"2.5.29.19", "Basic Constraints:"},
    {"1.3.6.1.5.5.7.3.2", "id_kp_clientAuth: True"}};

map<string, string> mapping2 = {
    {"1.2.840.10045.3.1.7", "SEC 2 recommended elliptic curve domain: "},
    {"2.5.29.35", "Authority Key Identifier: "},
    {"2.5.29.14", "Subject Key Identifier: "}};

map<string, string> mapping3 = {
    {"1.3.6.1.5.5.7.2.1", "OID for CPS qualifier: "},
    {"1.3.6.1.5.5.7.48.1", "OCSP: "},
    {"1.3.6.1.5.5.7.48.2", "id-ad-caIssuers: "},
    {"1.3.6.1.4.1.311.60.2.1.1", "Locality: "},
    {"1.3.6.1.4.1.311.60.2.1.3", "Country: "},
    {"1.3.6.1.4.1.311.60.2.1.2", "State or province: "},
    {"2.5.4.3", "common name: "},
    {"2.5.4.5", "serial number: "},
    {"2.5.4.6", "country name: "},
    {"2.5.4.7", "locality name: "},
    {"2.5.4.8", "stateOrProvince name: "},
    {"2.5.4.9", "streetAddress: "},
    {"2.5.4.10", "organization name: "},
    {"2.5.4.11", "organizational unit name: "},
    {"2.5.4.12", "title: "},
    {"2.5.4.13", "description: "},
    {"2.5.4.15", "businessCategory: "},
    {"2.5.29.32", "Certificate Policies: "},
    {"2.5.29.15", "Key Usage: "},
    {"2.5.29.17", "owner: "}};

map<string, string> algorithmMapping = {{"1.2.840.10040.4.1", "DSA"},
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
        // int year = (time[0] - '0') * 10 + (time[1] - '0') + 1970;
        printf("20%c%c year, %c%c month, %c%c day, %c%c:%c%c:%c%c \n", time[0],
               time[1], time[2], time[3], time[4], time[5], time[6], time[7],
               time[8], time[9], time[10], time[11]);
    }

  public:
    vector<Field> tokens;
    Certificate() { cur = 0; }
    ~Certificate() {}

    void printCertificate() {
        printf("the amount of tokens: %d\n", tokens.size());
        while (nextToken()) {
            if (token.tag == VERSION) {
                printf("%s: ", VERSION_STR.c_str());
                nextToken();
                printf("%d\n", token.valueVec[0] + 1);
                nextToken();
                printf("%s: ", "Sequence");
                printVec(token.valueVec);

            } else if (token.tag == OBJECT) {
                if (algorithmMapping.find(token.valueStr) !=
                    algorithmMapping.end()) {
                    printf("Algorithm: %s\n",
                           algorithmMapping[token.valueStr].c_str());

                } else if (mapping1.find(token.valueStr) != mapping1.end()) {
                    printf("%s\n", mapping1[token.valueStr].c_str());
                } else if (mapping2.find(token.valueStr) != mapping2.end()) {
                    printf("%s\n", mapping2[token.valueStr].c_str());
                    if (this->tokens[cur].valueVec.size() != 0) {
                        nextToken();
                        printVec(token.valueVec);
                    }
                } else if (mapping3.find(token.valueStr) != mapping3.end()) {
                    printf("%s\n", mapping3[token.valueStr].c_str());
                    if (this->tokens[cur].valueStr != "") {
                        nextToken();
                        printf("  %s\n", token.valueStr.c_str());
                    }
                } else {
                    printf("unknown object identifier: %s\n",
                           token.valueStr.c_str());
                }
            } else if (token.tag == UTCTIME) {
                printf("Validity: \n");
                printf("  not before: ");
                printTime(token.valueStr);
                nextToken();
                printf("  not after: ");
                printTime(token.valueStr);
            } else if (token.tag == STRUCTURE || token.tag == SET ||
                       token.tag == EXTENSION || token.tag == PUBLICKEY) {
                // printf("\n");
            } else if (token.tag == SPEIA5STRING || token.tag == IA5STRING ||
                       token.tag == PRINTABLE || token.tag == SUBJECTID) {
                printf("  %s\n", token.valueStr.c_str());
            } else if (token.tag == OUTPUT) {
                printf("  ");
                printVec(token.valueVec);
            } else if (token.valueStr == "") {
                printf("%s: ", tagName[token.tag].c_str());
                printVec(token.valueVec);

            } else {
                printf("%s:  %s\n", tagName[token.tag].c_str(),
                       token.valueStr.c_str());
            }
        }
    }

    bool nextToken() {
        if (cur >= this->tokens.size()) {
            return false;
        }
        token = this->tokens[cur];
        cur++;
        return true;
    }
};