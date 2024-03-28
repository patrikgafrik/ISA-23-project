// ISA - DNS resolver
// Autor: Patrik Gáfrik
// Login: xgafri00
// Ak. rok: 2023/2024

#include <stdio.h>
#include <time.h>
#include <string.h>
#include <vector>
#include <getopt.h>
#include <iostream>
#include <cstdlib>
#include <string>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>

void printName(uint8_t *name, uint8_t* header);
bool isCompressed(uint8_t *name);
uint8_t getNameLength(uint8_t* name);


struct request_flags {
    bool r_flag = false;
    bool x_flag = false;
    bool ipv6_flag = false;
    const char *server;
    unsigned int port = 53;
    char *address;
};

struct DNS_header {
    uint16_t id;
    uint16_t flags;
    uint16_t q_count;
    uint16_t a_count;
    uint16_t ns_count;
    uint16_t add_count;
};

struct DNS_question {
    char *name;
    uint16_t type;
    uint16_t _class;

};

struct DNS_record {
    uint16_t type;
    uint16_t _class;
    uint32_t ttl;
    uint16_t length;
} __attribute((packed));

void parseAnswerSection(uint8_t **name_start, DNS_record **records, DNS_header **header, uint8_t **rdata, uint16_t **records_offset, uint8_t *name_length);
void parseAuthoritySection(uint8_t **name_start, DNS_record **records, DNS_header **header, uint8_t **rdata, uint16_t **records_offset, uint8_t *name_length);
void parseAdditionalSection(uint8_t **name_start, DNS_record **records, DNS_header **header, uint8_t **rdata, uint16_t **records_offset, uint8_t *name_length);

void handleArgs(int argc, char* argv[], request_flags &args) {

    int option;
    while ((option = getopt(argc, argv, "rx6s:p:")) != -1) {
        switch (option) {
            case 'r':
                args.r_flag = true;
                break;
            case 'x':
                args.x_flag = true;
                break;
            case '6':
                args.ipv6_flag = true;
                break;
            case 's':
                args.server = optarg;
                break;
            case 'p':
                args.port = std::atoi(optarg);
                break;
            case '?':
                std::cerr << "Usage: " << argv[0] << " [-r] [-x] [-6] -s server [-p port] address" << std::endl;
                exit(EXIT_SUCCESS);
        }
    }

    if (optind < argc) {
        args.address = argv[optind];
    } else {
        std::cerr << "Error: address is missing." << std::endl;
        exit(EXIT_FAILURE);
    }

}

/*
 * vytvorenie a poslanie DNS query paketu - implementácia prevziata z návodu OpenCSF
 * https://w3.cs.jmu.edu/kirkpams/OpenCSF/Books/csf/html/UDPSockets.html#id1
 * created by Michael S. Kirkpatrick
 * licensed under https://creativecommons.org/licenses/by-sa/4.0/
*/
void constructDNSPacket(int socket, request_flags &args) {

    DNS_header header;
    memset(&header, 0, sizeof(struct DNS_header));
    srand(time(NULL));
    header.id = htons(rand() % 65536);
    uint16_t flags = 0;
    flags |= (1 << 8);

    if (args.r_flag) {
        header.flags = ntohs(flags);
    }
    else {
        header.flags = 0;
    }
    header.q_count = htons(1);

    DNS_question question;
    if (!args.ipv6_flag) {
        question.type = htons(1);
    }
    else {
        question.type = htons(28);
    }

    question._class = htons(1);
    question.name = (char*)calloc(strlen(args.address) + 2, sizeof(char));
    memcpy(question.name + 1, args.address, strlen(args.address));
    uint8_t *prev = (uint8_t*) question.name;
    uint8_t count = 0;
    for (size_t i = 0; i < strlen(args.address); i++) {
        if (args.address[i] == '.') {
            *prev = count;
            prev = (uint8_t*) question.name + i + 1;
            count = 0;
        }
        else {
            count++;
        }
        *prev = count;
    }

    size_t packetlen = sizeof(header) + strlen(args.address) + 2 + sizeof(question.type) + sizeof(question._class);
    uint8_t *packet = (uint8_t*) calloc(packetlen, sizeof(uint8_t));
    uint8_t *p = (uint8_t*) packet;
    memcpy (p, &header, sizeof (header));
    p += sizeof (header);
    memcpy (p, question.name, strlen (args.address) + 1);
    p += strlen (args.address) + 2;
    memcpy(p, &question.type, sizeof(question.type));
    p += sizeof(question.type);
    memcpy(p, &question._class, sizeof(question._class));


    int sent = send(socket, packet, packetlen, 0);
    if (sent == -1) {
        exit(EXIT_FAILURE);
    }


}

/*
 * spracovanie DNS odpovedi - implementácia po riadok 196 prevziata z návodu OpenCSF
 * https://w3.cs.jmu.edu/kirkpams/OpenCSF/Books/csf/html/UDPSockets.html#id1
 * created by Michael S. Kirkpatrick
 * licensed under https://creativecommons.org/licenses/by-sa/4.0/
*/
void getDNSAnswer(int socket, struct addrinfo *result, struct addrinfo *rp) {

    uint8_t response[512];
    memset(&response, 0, 512);

    ssize_t bytes = recvfrom(socket, response, 512, 0, rp->ai_addr, (socklen_t *) &(rp->ai_addrlen));
    if (bytes == -1) {
        fprintf(stderr, "Error receiving response!");
        exit(EXIT_FAILURE);
    }
    close(socket);
    freeaddrinfo(result);

    DNS_header *header = (DNS_header*) response; // ukazuje na začiatok paketu s odpoveďou a zaberá 12 bajtov
    if ((ntohs(header->flags) & 0xf) != 0) {
        fprintf(stderr, "Error: RCODE 1");
        exit(EXIT_FAILURE);
    }

    uint8_t *start_of_name = (uint8_t*) (response + sizeof(DNS_header));
    uint8_t total = 0;
    uint8_t *field_length = start_of_name;

    while(*field_length != 0) {
        total += *field_length + 1;
        field_length = start_of_name + total;
    }

    // kontrola bitu AA vo Flags časti headeru
    if (((ntohs(header->flags) >> 10) & 1) == 1) {
        printf("Authoritative: Yes, ");
    }
    else {
        printf("Authoritative: No, ");
    }
    // kontrola bitu RD vo Flags časti headeru
    if (((ntohs(header->flags) >> 8) & 1) == 1) {
        printf("Recursive: Yes, ");
    }
    else {
        printf("Recursive: No, ");
    }
    // kontrola bitu TC vo Flags časti headeru
    if (((ntohs(header->flags) >> 9) & 1) == 1) {
        printf("Truncated: Yes\n");
    }
    else {
        printf("Truncated: No\n");
    }
    printf("\n");
    printf("Question section (%d)\n", ntohs(header->q_count));
    printName(start_of_name, (uint8_t*)header);
    printf(", ");

    uint16_t *qtype = (uint16_t*)(field_length + 1);
    uint16_t *qclass = (uint16_t*)(field_length + 3);

    if (ntohs(*qtype) == 1) {
        printf("A, ");
    }
    else if (ntohs(*qtype) == 28) {
        printf("AAAA, ");
    }

    if (ntohs(*qclass) == 1) {
        printf("IN\n");
    }
    printf("\n");
    printf("Answer section (%d)\n", ntohs(header->a_count));

    field_length += 5;
    uint8_t *name_start = field_length; // ukazuje na prvý byte záznamu (name)
    uint8_t name_length = getNameLength(name_start);
    uint16_t *start_of_records = (uint16_t *)(field_length + name_length);
    DNS_record *records = (DNS_record*) (start_of_records); // ukazuje na časť záznamu od Type po RDATA Length (10 bajtov)
    uint8_t *rdata = field_length + 10 + name_length; // ukazuje na prvý byte časti RDATA
    uint16_t *records_offset = NULL;

    parseAnswerSection(&name_start, &records, &header, &rdata, &records_offset, &name_length);

    printf("\n");
    printf("Authority section (%d)\n", ntohs(header->ns_count));

    parseAuthoritySection(&name_start, &records, &header, &rdata, &records_offset, &name_length);

    printf("\n");
    printf("Additional section (%d)\n", ntohs(header->add_count));

    parseAdditionalSection(&name_start, &records, &header, &rdata, &records_offset, &name_length);

}

void parseAnswerSection(uint8_t **name_start, DNS_record **records, DNS_header **header, uint8_t **rdata, uint16_t **records_offset, uint8_t *name_length) {

    char addr_str[INET6_ADDRSTRLEN];
    int i = 0;
    while (i < ntohs((*header)->a_count)) {

        switch(ntohs((*records)->type)) {

            case 1:
                printName(*name_start, (uint8_t*)*header);
                printf(", ");
                printf("A, ");
                if (ntohs((*records)->_class) == 1) printf("IN, ");
                printf("%d, ", ntohl((*records)->ttl));
                inet_ntop(AF_INET, (*rdata), addr_str, INET_ADDRSTRLEN);
                printf("%s\n", addr_str);
                (*name_start) += (*name_length) + 10 + ntohs((*records)->length);
                (*rdata) += (*name_length) + 10 + ntohs((*records)->length);
                (*records_offset) = (uint16_t *)(((uint8_t*) (*records)) + 10 + ntohs((*records)->length) + (*name_length));
                (*records) = (DNS_record*)(*records_offset);
                break;

            case 5:
                printName((*name_start), (uint8_t*)*header);
                printf(", ");
                printf("CNAME, ");
                if (ntohs((*records)->_class) == 1) printf("IN, ");
                printf("%d, ", ntohl((*records)->ttl));
                printName((*rdata), (uint8_t*)*header);
                printf("\n");
                (*name_start) += (*name_length) + 10 + ntohs((*records)->length);
                (*rdata) += (*name_length) + 10 + ntohs((*records)->length);
                (*records_offset) = (uint16_t *)(((uint8_t*) (*records)) + 10 + ntohs((*records)->length) + (*name_length));
                (*records) = (DNS_record*)(*records_offset);
                break;

            case 28:
                printName((*name_start), (uint8_t*)*header);
                printf(", ");
                printf("AAAA, ");
                if (ntohs((*records)->_class) == 1) printf("IN, ");
                printf("%d, ", ntohl((*records)->ttl));
                printName((*rdata), (uint8_t*)*header);
                printf("\n");
                (*name_start) += (*name_length) + 10 + ntohs((*records)->length);
                (*rdata) += (*name_length) + 10 + ntohs((*records)->length);
                (*records_offset) = (uint16_t *)(((uint8_t*) (*records)) + 10 + ntohs((*records)->length) + (*name_length));
                (*records) = (DNS_record*)(*records_offset);
                break;

            default:
                break;
        }

        i++;

    }
}

void parseAuthoritySection(uint8_t **name_start, DNS_record **records, DNS_header **header, uint8_t **rdata, uint16_t **records_offset, uint8_t *name_length) {

    int i = 0;
    while(i < ntohs((*header)->ns_count)) {


        printName((*name_start), (uint8_t*)(*header));
        printf(", ");
        if (ntohs((*records)->type) == 2) {
            printf("NS, ");
        }
        if (ntohs((*records)->_class) == 1) {
            printf("IN, ");
        }
        printf("%d, ", ntohl((*records)->ttl));


        uint8_t *pos = (*rdata);
        printName(pos, (uint8_t *)(*header));
        printf("\n");
        (*name_start) += (*name_length) + 10 + ntohs((*records)->length);
        (*name_length) = getNameLength((*name_start));
        (*rdata) += 10 + ntohs((*records)->length) + (*name_length);
        (*records_offset) = (uint16_t *)(((uint8_t*) (*records)) + 10 + ntohs((*records)->length) + (*name_length));
        (*records) = (DNS_record*)(*records_offset);
        i++;

    }
}


void parseAdditionalSection(uint8_t **name_start, DNS_record **records, DNS_header **header, uint8_t **rdata, uint16_t **records_offset, uint8_t *name_length) {

    char addr_str[INET6_ADDRSTRLEN];
    int i = 0;
    while(i < ntohs((*header)->add_count)) {

        switch(ntohs((*records)->type)) {

            case 1:
                printName((*name_start), (uint8_t*)(*header));
                printf(", ");
                printf("A, ");
                if (ntohs((*records)->_class) == 1) printf("IN, ");
                printf("%d, ", ntohl((*records)->ttl));
                inet_ntop(AF_INET, (*rdata), addr_str, INET_ADDRSTRLEN);
                printf("%s\n", addr_str);
                (*name_start) += (*name_length) + 10 + ntohs((*records)->length);
                (*name_length) = getNameLength((*name_start));
                (*rdata) += 10 + ntohs((*records)->length) + (*name_length);
                (*records_offset) = (uint16_t *)(((uint8_t*) (*records)) + 10 + ntohs((*records)->length) + (*name_length));
                (*records) = (DNS_record*)(*records_offset);
                break;

            case 28:
                printName((*name_start), (uint8_t*)(*header));
                printf(", ");
                printf("AAAA, ");
                if (ntohs((*records)->_class) == 1) printf("IN, ");
                printf("%d, ", ntohl((*records)->ttl));
                inet_ntop(AF_INET6, (*rdata), addr_str, INET6_ADDRSTRLEN);
                printf("%s\n", addr_str);
                (*name_start) += (*name_length) + 10 + ntohs((*records)->length);
                (*name_length) = getNameLength((*name_start));
                (*rdata) += 10 + ntohs((*records)->length) + (*name_length);
                (*records_offset) = (uint16_t *)(((uint8_t*) (*records)) + 10 + ntohs((*records)->length) + (*name_length));
                (*records) = (DNS_record*)(*records_offset);
                break;

            default:
                break;
        }
        i++;

    }

}

uint8_t getNameLength(uint8_t* name) {
    uint8_t count = 0;
    uint8_t *curr = name;
    bool compressed = false;
    while(*curr != 0) {
        if (isCompressed(name)) {
            compressed = true;
        }
        count++;
        curr++;
    }
    if (compressed) {
        return count;
    }
    else {
        // pokiaľ nebola nájdená kompresia v Name, nezapočíta sa null terminator, treba ku count pripočítať +1
        return count + 1;
    }
}

void printName(uint8_t *name, uint8_t *header) {
    uint8_t *curr = name;

    while (*curr != 0) {
        if ((*curr & 0xc0) == 0xc0) {
            uint16_t offset = ((*curr & 0x3F) << 8) | *(curr + 1);
            printName(header + offset, header);
            break;
        }
        else {
            uint8_t labelLength = *curr;

            for (int i = 0; i < labelLength; ++i) {
                putchar(*(curr + 1 + i));
            }
            putchar('.');
            curr += labelLength + 1;
        }
    }
}

bool isCompressed(uint8_t *name) {
    uint8_t *curr = name;
    if ((*curr & 0xc0) == 0xc0) {
        return true;
    }
    else {
        return false;
    }
}

int main(int argc, char* argv[]) {

    struct request_flags args;
    handleArgs(argc, argv, args);

    /*
     * nadviazanie komunikácie s DNS serverom - implementácia prevziata z manuálu getaddrinfo()
     * https://man7.org/linux/man-pages/man3/getaddrinfo.3.html
     * created 2023-06-24 by Michael Kerrisk, author of The Linux Programming Interface.
    */
    int sfd, s;
    struct addrinfo hints;
    struct addrinfo *result, *rp;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = 0;
    hints.ai_protocol = 0;

    s = getaddrinfo(args.server, std::to_string(args.port).c_str(), &hints, &result);
    if (s != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
    }

    rp = result;
    while(rp != NULL) {
        sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sfd == -1) {
            continue;
        }
        if (connect(sfd, rp->ai_addr, rp->ai_addrlen) != -1) {
            break;
        }
        rp = rp->ai_next;
        close(sfd);
    }
    if (rp == NULL) {
        fprintf(stderr, "Could not connect\n");
        exit(EXIT_FAILURE);
    }

    constructDNSPacket(sfd, args);
    getDNSAnswer(sfd, result, rp);


    return 0;

}
