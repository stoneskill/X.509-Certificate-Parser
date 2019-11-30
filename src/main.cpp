#include "certificate.h"
#include "x509.h"
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <string>
using namespace std;
#define MAXN 200

int main(int argc, char **argv) {
    if (argc < 1) {
        perror("parameters error\n");
        exit(1);
    }
    ifstream certificateFile(argv[1]);
    if (!certificateFile.is_open()) {
        perror("cannot open file\n");
        exit(1);
    }

    string cert;
    char buffer[MAXN + 5];
    while (certificateFile.peek() != EOF) {
        certificateFile.getline(buffer, MAXN);
        string line=string(buffer);
        if (line.find("BEGIN") != -1) {
            continue;
        } else if (line.find("END") != -1) {
            break;
        } else {
            cert += line;
        }
    }
    if (cert.length() == 0) {
        perror("empty file\n");
        exit(1);
    }
    
    X509 x;
    Certificate c = x.parseCRT(cert);
    c.printCertificate();

    return 0;
}