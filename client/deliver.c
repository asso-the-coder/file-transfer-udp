#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <math.h>
#include <libgen.h>
#include <assert.h>
#include <stdbool.h>
#include <time.h>
#include <errno.h>

// Define packet struct
typedef struct {
    unsigned int total_frag; // number of packets to be sent for the total file
    unsigned int frag_no; // this specific packet's sequence number (packet-specific)
    unsigned int size; // this packet's size (packet-specific)
    char *filename;    // total file's filename
    char filedata[1000];    // payload (packet-specific)
} Packet;

#define MESSAGE_SIZE 1100  // header + data < 1100 bytes (arbitrary but principled)
#define RTT_MILLISECONDS 1.5 // round-trip time measured for test network
#define FOS 2.0 // arbitrary but principled timeout Factor of Safety (Karn's Rule)

// Prototypes
long get_file_size_ftell(FILE *file);
int read_bytes(FILE *file, char *buffer, int payload_size);
int construct_message(Packet *pkt, char* msg);

int main(int argc, char *argv[]) {

    // Receive and parse user input
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <server_address> <server_port_number>\n", argv[0]);
        return 1;
    }
    printf("Connecting to %s on port %s...\n", argv[1], argv[2]);
    const char *server_ip = argv[1];
    int server_port = atoi(argv[2]);

    // Prompt for file (using fgets to read the line, and sscanf to parse it)
    char user_input[1024], command[30], filepath[900];
    printf("Enter file transfer request. Expected format: 'ftp <file>'\n");
    fgets(user_input, sizeof(user_input), stdin);
    sscanf(user_input, "%s %s", command, filepath);
    
    // Check if file exists (using the unix standard access function)
    if (access(filepath, F_OK) != 0) {
        fprintf(stderr, "ftp not inserted at beginning or the following file does not exist: %s\n" \
            , filepath);
        return 1;
    }

    // Create address object compatible with socket
    struct sockaddr_in server_addr = {.sin_family = AF_INET, .sin_port = htons(server_port)};
    if (inet_pton(AF_INET, server_ip, &(server_addr.sin_addr)) <= 0) {
        perror ("Something wrong with the IP address");
        return 1;
    }

    // Initialize socket 
    int udp_socket = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_socket < 0) {
        perror ("Sorry, couldn't create the socket");
        return 1;
    }

    // Initialize timeout features in our socket
    struct timeval timeout;
    timeout.tv_sec = 0;
    timeout.tv_usec = (RTT_MILLISECONDS * 1000.0) * FOS;
    if (setsockopt(udp_socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        perror("setsockopt failed");
        return 1;
    }
    
    // Send a "handshake" packet through the socket (and error check)
    char *message = "ftp";
    if (sendto(udp_socket, message, strlen(message) + 1, 0, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Failed to send message");
        close(udp_socket);
        return 1;
    }
    printf("Sent  \"%s\" to %s:%d\n", message, server_ip, server_port);

    // Receive and parse handshake reply
    char reply[64];
    int bytes_received = recvfrom(udp_socket, reply, sizeof(reply), 0, NULL, NULL);
    if (bytes_received < 0) {
        perror("Error receiving");
        close(udp_socket);
        return 1;
    }
    printf("Reply received...\n");

    // Check if reply is "yes". If so, handshake is complete and file transfer can begin!
    if (strcmp(reply, "yes") == 0) {
        printf("Reply was 'yes'. A file transfer can start.\n");
    } else {
        printf("Reply was no. We not cool.\n");
        return 1;
    }

    /********************************** FILE TRANSFER ********************************************************************* */

    // Re-usable file pointer (open file in read-binary mode)
    FILE *file_ptr = fopen(filepath, "rb");
    if (!file_ptr){
        perror("Could not open READ filestream");
        return -1;
    }

    // Isolate name from path
    char *fname = basename(strdup(filepath));

    // Determine how many packets needed
    long long file_size = get_file_size_ftell(file_ptr);
    unsigned int total_fragments = ceil(file_size / 1000.0);
    printf("\nFile is called %s with size %lld bytes and should have %d frags.", \
        fname, file_size, total_fragments);

    // Create a single packet that we will re-populate continuously!
    Packet packet;

    // Initialize buffers, pointers, and logic for file transfer 
    long remaining_file_size = file_size;
    char ftp_message_tx[MESSAGE_SIZE] = {0}; // (header + data comprise one message)
    char received_ack[100];
    bool successful_send = true;

    // Populate, send, and receive ACKs for packets
    for (unsigned int i = 0; i < total_fragments; i++){
        
        // Populate packet
        packet.total_frag = total_fragments;
        packet.frag_no = i + 1; // naming starts from 1
        packet.filename = fname;

        // Last packet gets a different sizing (file remnants)
        if (i != total_fragments - 1){
            packet.size = 1000;
        } else {
            packet.size = remaining_file_size;
        }

        // Obtain the payload of the packet from source file
        if (read_bytes(file_ptr, packet.filedata, packet.size) < 0){
            perror("Error reading file!");
            fclose(file_ptr);
            close(udp_socket);
            return -1;
        }
        remaining_file_size -= packet.size; // update file remnants

        // Construct message
        if (construct_message(&packet, ftp_message_tx) < 0){
            perror("Could not construct message");
            fclose(file_ptr);
            close(udp_socket);
            return -1;
        }

        // Send packet and check ACK against timeout
        successful_send = false;
        while (successful_send == false){

            // Send packet
            if (sendto(udp_socket, ftp_message_tx, MESSAGE_SIZE, 0, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
                perror("Failed to send packet message");
                fclose(file_ptr);
                close(udp_socket);
                return 1;
            }

            // Move on only if ACK received, otherwise resend upon timeout
            bytes_received = recvfrom(udp_socket, received_ack, sizeof(received_ack), 0, NULL, NULL);
            if (bytes_received < 0){

                // Timeout condition
                if (errno == EAGAIN || errno == EWOULDBLOCK){
                    printf("\nTimeout while attempting to send Packet #%d. Re-sending...\n", packet.frag_no);
                    continue;
                }

                // Other error (fatal)
                else {
                    perror("Error receiving packets from server.");
                    close(udp_socket);
                    return 1;
                }
            }
            
            // Check the received ACK is correct (each msg has unique ACK)
            if ((unsigned int) atoi(received_ack) != packet.frag_no){
                perror("ACK is for the wrong packet. Re-send.");
                continue;
            } else {
                successful_send = true; // all checks passed for this packet. Reliable transmission complete.
            }
        }

        printf("\nSuccessfully sent Packet #%d to %s:%d", packet.frag_no, server_ip, server_port);
    }

    // Cleanups
    printf("\n\nFile transfer complete.\n");
    fclose(file_ptr);
    close(udp_socket);

    return 0;
}

// Getting file size to make fragments
long get_file_size_ftell(FILE *file) {
    
    if (file == NULL) {
        perror("Error opening file");
        return -1; 
    }

    // Traverse to end of file
    if (fseek(file, 0, SEEK_END) != 0) {
        perror("Error seeking to end");
        fclose(file);
        return -1;
    }

    // Get the current position, which is the file size
    long size = ftell(file);
    if (size == -1) {
        perror("Error getting file position");
        fclose(file);
        return -1;
    }

    // Rewind file pointer position back to the beginning!
    rewind(file);

    return size;
}

// Reading file to be transmitted
int read_bytes(FILE *file, char *buffer, int payload_size){

    // Standard file read
    int bytes_read = fread(buffer, 1, payload_size, file);  
    if (bytes_read != payload_size){
        perror("Error reading file!");
        fclose(file);
        return -1;
    }

    return bytes_read; 
}

// Constructing full datagram
int construct_message(Packet *pkt, char* msg){

    // Make header
    int header_len = snprintf(msg, MESSAGE_SIZE, "%u:%u:%u:%s:", \
    pkt->total_frag, pkt->frag_no, pkt->size, pkt->filename);

    if (header_len < 0){
        perror("Could not create header!");
        return -1;
    }

    // Go to msg and begin writing the binary payload after the header length
    memcpy(msg + header_len, pkt->filedata, pkt->size);

    // Sanity check that message size is equal to header + payload + colons
    //assert(size of the message == header + pkt->size + 4);

    return header_len + (int)pkt->size;
}