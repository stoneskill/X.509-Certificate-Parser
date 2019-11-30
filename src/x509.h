#pragma once
#include "certificate.h"
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>
using std::string;
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
        string name = "", value = "";
        TLV t(this->cerText);
        begin += t.offset;
        // i += t.length;
        switch (t.tag) {
        case STRUCTURE: // structure
        case SET:       // set
            parse(begin, begin + t.length);
            break;

        case VERSION: // version
            certificate.tokens.push_back(Field(t.tag, t.value));
            parse(begin, begin + t.length);
            break;
        case 0xa3: // extention
            certificate.tokens.push_back(Field(t.tag, t.value));
            parse(begin, begin + t.length);
            break;

        case 0x1: // boolean
            name = "boolean";
            if (t.value[0] == 0) {
                value = "FALSE";
            } else
                value = "TRUE";
            certificate.tokens.push_back(Field(t.tag, value));

            break;
        case 0x2: // integer
            name = "integer";
            certificate.tokens.push_back(Field(t.tag, t.value));
            break;
        case 0x3: // bit string
            name = "bit string";
            certificate.tokens.push_back(Field(t.tag, t.value));
            break;
        case 0x4: // octet string
            parse(begin, begin + t.length);
            break;
        case 0x5:
            break;
        case 0x6: // object identifier
            name = "";
            v1 = cerText[begin] / 40;
            v2 = cerText[begin] - v1 * 40;
            name += to_string(v1);
            name += ".";
            name += to_string(v2);
            name += ".";
            temp = 0;
            for (j = begin; j < end; j++) {
                temp <<= 7;
                temp += cerText[j] & 0x7f;
                if (cerText[j] & 0x80 == 0) {
                    name += to_string(temp);
                    name += ".";
                    temp = 0;
                }
            }
            certificate.tokens.push_back(Field(t.tag, t.value));
            break;
        case 0x17: // time
            name = "UTCTime";
        case 0x13: // string
        case 0x82: // subjectUniqueID
        case 0x16: // IA5String
        case 0xc:  // UTF8String
        case 0x86: // IA5String
            for (j = begin; j < end; j++) {
                name += to_string(cerText[j]);
            }
            certificate.tokens.push_back(Field(t.tag, t.value));
            break;
        case 0x80:
            certificate.tokens.push_back(Field(t.tag, t.value));
            break;

        default:
            parse(begin, end);
            break;
        }
    }

  public:
    X509() {}
    ~X509() {}
    Certificate parseCRT(string cert) {
        if (cert.length() % 4 != 0) {
            perror("error certificate");
            exit(0);
        }
        // base64 -> binary
        char temp[4];
        for (int i = 0; i < cert.length(); i++) {
            for (int j = 0; j < 4; j++) {
                temp[j] = lookupTable.find(cert[i + j]);
            }
            cerText.push_back(((temp[0] & 0x3f) << 2) |
                              ((temp[1] & 0x30) >> 4));
            cerText.push_back(((temp[1] & 0xf) << 4) | ((temp[2] & 0x3c) >> 2));
            cerText.push_back(((temp[2] & 0x3) << 6) | (temp[3] & 0x3f));
        }
        parse(0, cert.length());
    }
};