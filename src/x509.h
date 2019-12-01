#pragma once
#include "certificate.h"
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>
using std::string;
using std::to_string;
using std::vector;

static const string lookupTable = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                  "abcdefghijklmnopqrstuvwxyz"
                                  "0123456789+/";
class X509 {
  private:
    vector<unsigned char> cerText;
    Certificate certificate;
    void parse(int begin, int end) {
        int v1 = 0, v2 = 0, temp = 0;
        int j = 0;
        string value = "";
        while (begin < end) {
            TLV t(this->cerText, begin);
            // printf("%u %d %d\n",t.tag,t.length,t.offset);
            begin += t.offset;
            if (begin >= end) {
                break;
            }
            switch (t.tag) {
            case STRUCTURE: // structure
            case SET:       // set
                parse(begin, begin + t.length);
                break;

            case EXTENSION: // extention
            case VERSION:   // version
                certificate.tokens.push_back(Field(t.tag, t.value));
                parse(begin, begin + t.length);
                break;

            case BOOLEAN: // boolean
                if (t.value[0] == 0) {
                    value = "FALSE";
                } else
                    value = "TRUE";
                certificate.tokens.push_back(Field(t.tag, value));
                break;

            case OUTPUT:
            case INTEGER: // integer
                certificate.tokens.push_back(Field(t.tag, t.value));
                break;
            case BITSTRING: // bit string
                certificate.tokens.push_back(Field(t.tag, t.value));
                break;
            case PUBLICKEY:
                certificate.tokens.push_back(Field(t.tag, t.value));
                break;
            case OCTETSTRING: // octet string
                // certificate.tokens.push_back(Field(t.tag, t.value));
                parse(begin, begin + t.length);
                break;
            case NUL:
                break;
            case OBJECT: // object identifier
                value = "";
                v1 = cerText[begin] / 40;
                v2 = cerText[begin] - v1 * 40;
                value += to_string(v1);
                value += ".";
                value += to_string(v2);
                value += ".";
                temp = 0;
                for (j = begin + 1; j < begin + t.length; j++) {
                    temp <<= 7;
                    temp += cerText[j] & 0x7f;
                    if ((cerText[j] & 0x80) == 0) {
                        value += to_string(temp);
                        if (j < begin + t.length - 1)
                            value += ".";
                        temp = 0;
                    }
                }
                certificate.tokens.push_back(Field(t.tag, value));
                break;
            case UTCTIME:      // time
            case PRINTABLE:    // string
            case SUBJECTID:    // subject id
            case IA5STRING:    // IA5String
            case SPEIA5STRING: // IA5String
                value = "";
                for (j = begin; j < begin + t.length; j++) {
                    value += char(cerText[j]);
                }
                certificate.tokens.push_back(Field(t.tag, value));
                break;

            default:
                // printf("unknown tag: %u\n",t.tag);
                // exit(1);
                return;
                // break;
            }
            begin += t.length;
        }
    }

  public:
    X509() {}
    ~X509() {}
    Certificate parseCRT(string cert) {
        certificate = Certificate();
        cerText.clear();
        if (cert.length() % 4 != 0) {
            perror("error certificate");
            exit(0);
        }
        // base64 -> binary
        char temp[4];
        for (int i = 0; i < cert.length(); i += 4) {
            for (int j = 0; j < 4; j++) {
                temp[j] = lookupTable.find(cert[i + j]);
            }
            cerText.push_back(((temp[0] & 0x3f) << 2) |
                              ((temp[1] & 0x30) >> 4));
            cerText.push_back(((temp[1] & 0xf) << 4) | ((temp[2] & 0x3c) >> 2));
            cerText.push_back(((temp[2] & 0x3) << 6) | (temp[3] & 0x3f));
        }
        // for (int i = 0; i < cerText.size(); i++) {
        //     printf("%u ", cerText[i]);
        // }
        // printf("\n");
        parse(0, cert.length());
        return certificate;
    }
};