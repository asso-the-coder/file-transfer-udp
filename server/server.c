#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <time.h>

// Define packet struct
typedef struct {
    unsigned int total_frag; // number of packets to be sent for the total file
    unsigned int frag_no; // this specific packet's sequence number (packet-specific)
    unsigned int size; // this packet's size (packet-specific)
    char *filename;    // total file's filename
    char filedata[1000];    // payload (packet-specific)
} Packet;

#define MESSAGE_SIZE 1100 // header + data < 1100 bytes (arbitrary but principled)
#define PACKET_LOSS_PERCENTAGE 10  // adjust this to test ARQ

// Prototypes
int parse_message(Packet *pkt, char* msg, char* filename_received);

int main(int argc, char *argv[]) {

    // Receive and parse user input
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <udp_listen_port>\n", argv[0]);
        return 1;
    }
    printf("Server running. UDP Listening on port %s...\n", argv[1]);
    const int my_port = atoi(argv[1]);

    // Create address objects for local address and eventual client address
    struct sockaddr_in client_addr;
    struct sockaddr_in server_addr = {.sin_family = AF_INET, 
                                        .sin_addr.s_addr = htonl(INADDR_ANY),
                                        .sin_port = htons(my_port)};

    // Initialize socket
    int udp_socket = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_socket < 0) {
        perror ("Sorry, couldn't create the socket");
        return 1;
    }

    // Bind address and socket together
    if (bind(udp_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Error binding socket to local IP address");
        close(udp_socket);
        return 1;
    }

    // Receive message and record address of client
    char message_rx[64];
    int size_message_rx = 64;
    socklen_t client_len = sizeof(client_addr);
    int bytes_received = recvfrom(udp_socket, message_rx, size_message_rx, 0, (struct sockaddr*)&client_addr, &client_len);
    if (bytes_received < 0) {
        perror("Error receiving message from socket");
        close(udp_socket);
        return 1;
    }
    printf("Message received from client: %s\n", message_rx);

    // Check if message is "ftp" indicating a handshake request
    if (strcmp(message_rx, "ftp") != 0) {
        printf("Nothing shall be provided\n");
        close(udp_socket);
        return 1;
    }
    printf("Message matches 'ftp', attempting to send confirmation to client\n");

    // Send a packet through the socket (to client address recorded earlier) to complete handshake
    char *message_tx = "yes";
    if (sendto(udp_socket, message_tx, strlen(message_tx) + 1, 0, (struct sockaddr *)&client_addr, sizeof(client_addr)) < 0) {
        perror("Failed to send message");
        close(udp_socket);
        return 1;
    }

    // Handshake complete. File transfer can begin!
    printf("Sent \"%s\" back to client\n", message_tx);

    /********************************** FILE TRANSFER ********************************************************************* */

    // Create a single packet that we will re-populate continuously!
    Packet packet;

    // Initialize buffers and pointers for file transfer
    char ftp_message_rx[MESSAGE_SIZE];
    char filename_received[100]; 
    char ack_to_send[100];
    size_t written = 0;
    FILE *file_ptr = NULL;

    // Random number generation (for packet loss testing)
    srand(time(NULL));
    int random_num = 0;
    
    // Enter loop until last fragment
    unsigned int packets_received = 0;
    while (packets_received < packet.total_frag){

        // Receive packet
        bytes_received = recvfrom(udp_socket, ftp_message_rx, MESSAGE_SIZE, 0, (struct sockaddr*)&client_addr, &client_len);
        if (bytes_received < 0) {
            perror("Error receiving packet message from socket");
            close(udp_socket);
            return 1;
        }

        // Parse packet
        if (parse_message(&packet, ftp_message_rx, filename_received) < 0){
            perror("Error parsing data!");
            close(udp_socket);
            return -1;
        }
        packet.filename = filename_received;

        // The very first packet is used to create the file
        if (packets_received == 0){
            file_ptr = fopen(packet.filename, "wb");
            if (!file_ptr){
                perror("Could not open WRITE filestream");
                return -1;
            }
        }
        
        // Packet loss simulator (drop ACKs pseudo-randomly)
        random_num = (rand() % 100); // between 0 and 99
        if (random_num < PACKET_LOSS_PERCENTAGE){
            printf("\nPacket #%d ACK intentionally dropped.", packets_received + 1);
            continue;
        }

        // Acknowledge uniquely (send back frag number)
        snprintf(ack_to_send, sizeof(ack_to_send), "%d", packet.frag_no);
        if (sendto(udp_socket, ack_to_send, strlen(ack_to_send) + 1, 0, (struct sockaddr *)&client_addr, sizeof(client_addr)) < 0) {
            perror("Failed to send ACK");
            close(udp_socket);
            return 1;
        }

        // Write payload to filestream (IFF successfully received and ACK'd)
        written = fwrite(packet.filedata, 1, packet.size, file_ptr);
        if (written != packet.size) {
            perror("Error writing to filestream");
            fclose(file_ptr);
            return -1;
        }
        
        // Increment successfully received packets
        packets_received++;

    }

    // Cleanups when done
    printf("\n\nFile transfer complete. Received %d packets. See %s in this directory.\n", packets_received, packet.filename);
    fclose(file_ptr);
    close(udp_socket);

    return 0;
}

int parse_message(Packet *pkt, char* msg, char* filename_received){

    // Traversal pointer, placeholder buffer, and colon-separator location array
    char *msg_traversal_ptr = msg;
    char placeholder[MESSAGE_SIZE];
    unsigned int colon_positions[4] = {0};

    //printf("\nMessage is %s", msg_traversal_ptr);
    
    // Find all the colons
    memcpy(placeholder, msg_traversal_ptr, MESSAGE_SIZE);
    int i = 0;
    int colon_counter = 0;    
    while (colon_counter < 4){
        if (placeholder[i] == ':'){
            colon_positions[colon_counter] = i;
            colon_counter++;
        }
        i++;
    }

    /**  Using memset and memcpy everywhere for binary-safe data parsing **/

    // Traverse and parse the message using pointer math (accounting for colons!)
    memcpy(placeholder, msg_traversal_ptr, colon_positions[0]);
    msg_traversal_ptr += colon_positions[0] + 1;
    pkt->total_frag = atoi(placeholder);

    memset(placeholder, 0, MESSAGE_SIZE); //reset placeholder in between
    memcpy(placeholder, msg_traversal_ptr, colon_positions[1] - colon_positions[0] - 1);
    msg_traversal_ptr += colon_positions[1] - colon_positions[0];
    pkt->frag_no = atoi(placeholder);

    memset(placeholder, 0, MESSAGE_SIZE); 
    memcpy(placeholder, msg_traversal_ptr, colon_positions[2] - colon_positions[1] - 1);
    msg_traversal_ptr += colon_positions[2] - colon_positions[1];
    pkt->size = atoi(placeholder);

    memset(placeholder, 0, MESSAGE_SIZE); 
    memcpy(placeholder, msg_traversal_ptr, colon_positions[3] - colon_positions[2] - 1);
    msg_traversal_ptr += colon_positions[3] - colon_positions[2];
    strcpy(filename_received, placeholder);
    
    // No placeholder needed for payload (dump binary data straight in)
    memcpy(pkt->filedata, msg_traversal_ptr, pkt->size);

    return 0;
}

