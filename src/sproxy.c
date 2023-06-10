#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sys/select.h>
#include <sys/time.h>

#define MAX_LENTH 256
#define LOCALHOST "127.0.0.1"
#define TELPORT 23

typedef struct packet
{
    int data_len; // base length of message.
    int seq_num;  // a global variable which will ++ on each message sent.
    int ack_num;
    // we can send this value and have the other connection return it as an ACK
    unsigned int sessionID; // The session ID generated. We can use this to know if this is a continued telnet conn
                            // or a new one and handle it accordingly.
    char data[1028];        // The actual message to be sent, 256 might be too big.
    struct packet *next;    // Forms the LL
} packet;

//Struct for holding packets while connection is down.
//Enqueue and dequeue methods exist in this file for interaction with the LL.
typedef struct pack_queue
{
    int size;
    struct packet *head;
} pack_queue;

//Prototypes
void send_hb(int sock, unsigned int id, int seqN, int ackN);
int send_telnet(int sock, char *data, unsigned int data_len, int seqN, int ackN);
int time_dif(struct timeval *a, struct timeval *b);
void enqueue(pack_queue *queue, int data_len, const char *data, int seq_num, int ack_num);
void *dequeue(pack_queue *queue);

//Used to keep track of # and order of packets sent and
//which was the last packet acknowledged. 
int seqN = 0;
int ackN = 0;

int main(int argc, char const *argv[])
{
    char *sip = malloc(20); //The server IP address
    char s_buff[MAX_LENTH], c_buff[MAX_LENTH]; //Two buffers for holding messages sent and recieved.
    memset(c_buff, '\0', sizeof(c_buff));
    memset(s_buff, '\0', sizeof(s_buff));

    struct sockaddr_in cproxy_soc_addr, tnet_daem_soc_addr, accepted_soc_addr; //structs for establishing a connection and storing connection data.
    struct timeval select_timeout, cur_time, sent_time, recv_time; //These structs are used for timing the while loop.
    int accepted_soc_addr_len = sizeof(accepted_soc_addr);
    int cproxy_soc, telnet_daem_soc, new_cproxy_soc;
    int con_to_prox = 0;
    unsigned int session_id = 0xDEADBEEF;
    int select_retval;
    int s_port, c_port;
    int max_fd;
    int rv_telnet, rv_tnet_deam;
    int sd_max;
    pack_queue *queue = malloc(sizeof(pack_queue));
    queue->size = 0;

    fd_set readfd, readyfd;

    // check arg count
    if (argc != 2)
    {
        printf("Invalid args\t");
        printf("./sproxy <c_port>\n");
        printf("c_port - port cproxy connects to\n");
        return -1;
    }

    // grab data from argv
    c_port = atoi(argv[1]);

    // create a listening socket for cproxy to connect to.
    if (((cproxy_soc = socket(PF_INET, SOCK_STREAM, 0)) == 0))
    {
        perror("server_soc failed.");
    }

    // setup cproxy_soc_addr, will accept connection from cproxy.
    bzero(&cproxy_soc_addr, sizeof(cproxy_soc_addr));

    cproxy_soc_addr.sin_family = AF_INET;
    cproxy_soc_addr.sin_addr.s_addr = INADDR_ANY;
    cproxy_soc_addr.sin_port = htons(c_port);

    // setup tnet_daem_soc_addr, will connect immediately to local telnet.
    bzero(&tnet_daem_soc_addr, sizeof(tnet_daem_soc_addr));

    tnet_daem_soc_addr.sin_family = AF_INET;
    tnet_daem_soc_addr.sin_addr.s_addr = inet_addr(LOCALHOST);
    tnet_daem_soc_addr.sin_port = htons(TELPORT);

    // set up file descripter set and add the server socket
    FD_ZERO(&readfd);
    FD_SET(cproxy_soc, &readfd);
    sd_max = cproxy_soc + 1;
    // printf("Added cproxy_soc: %d to fd_set\nfd_setmax : %d\n",cproxy_soc, sd_max);fflush;

    // bind and listen to cproxy_soc
    if (bind(cproxy_soc, (struct sockaddr *)&cproxy_soc_addr, sizeof(cproxy_soc_addr)) < 0)
    {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }
    if (listen(cproxy_soc, 5) < 0)
    {
        perror("Listen");
        exit(EXIT_FAILURE);
    }

    // accept new connection to cproxy
    new_cproxy_soc = accept(cproxy_soc, (struct sockaddr *)&accepted_soc_addr, (socklen_t *)&accepted_soc_addr_len);
    // printf("new_cproxy_soc = %d\n", new_cproxy_soc);fflush;
    if (new_cproxy_soc < 0)
    {
        perror("Accpet Failed");
        exit(EXIT_FAILURE);
    }

    // add to FD_SET the new connection
    FD_SET(new_cproxy_soc, &readfd);
    if (new_cproxy_soc > sd_max)
    {
        sd_max = new_cproxy_soc + 1;
    }

    // Extracts and assigns header information from received data buffer.
    rv_telnet = recv(new_cproxy_soc, c_buff, 9, 0);
    long long header = strtoll(c_buff, NULL, 16);
    unsigned long type = (unsigned long)(header >> 33) & 0x1;
    unsigned int p_length = (unsigned int)(header >> 24) & 0x1ff;
    unsigned int rcv_seqN = (unsigned int)(header >> 12) & 0x000fff;
    unsigned int rcv_ackN = (unsigned int)header & 0x000000fff;
    ackN = rcv_seqN;
    printf("type: %lu\nlength: %d\nrecv_seqN: %d\nrecv_ackN: %d\n", type, p_length, rcv_seqN, rcv_ackN);
    fflush;
    memset(c_buff, '\0', sizeof(c_buff));

    // Get the payload
    rv_telnet = recv(new_cproxy_soc, c_buff, p_length, 0);
    gettimeofday(&recv_time, NULL);

    //If type == 0 then we recieved the first HB signal and are good on our connection to enter the
    //while loop.
    if (type == 0)
    {
        unsigned int temp = strtol(c_buff, NULL, 16);
        //The initial HB session ID.
        if (session_id == 0xDEADBEEF)
        {
            session_id = temp;
            // create client socket to be used pass data between sproxy and server telnet.
            if (((telnet_daem_soc = socket(PF_INET, SOCK_STREAM, 0)) == 0))
            {
                perror("server_soc failed.");
            }

            // connect to sproxy/server telnet
            if (connect(telnet_daem_soc, (struct sockaddr *)&tnet_daem_soc_addr, sizeof(tnet_daem_soc_addr)) < 0)
            {
                perror("Connect failed");
                exit(EXIT_FAILURE);
            }
            // printf("Telnet Deamon Connected\n");fflush;
            FD_SET(telnet_daem_soc, &readfd);
            if (telnet_daem_soc > sd_max)
            {
                sd_max = telnet_daem_soc + 1;
            }
        }
    }

    memset(c_buff, '\0', sizeof(c_buff));
    //Send first HB back.
    send_hb(new_cproxy_soc, session_id, seqN, ackN);
    gettimeofday(&sent_time, NULL);
    con_to_prox = 1;

    while (1)
    {
        // Reset all parameters of the select statement. Must be done for each pass of the while loop.
        select_timeout.tv_sec = 1;
        select_timeout.tv_usec = 0;
        readyfd = readfd;

        // wait for a socket to become ready
        select_retval = select(sd_max, &readyfd, NULL, NULL, &select_timeout);
        if (select_retval < 0)
        {
            perror("select error");
            exit(EXIT_FAILURE);
        }

        gettimeofday(&cur_time, NULL);

        // check if HB needs to be sent or we lost connection
        int last_HB = time_dif(&cur_time, &sent_time);
        int last_Rcv = time_dif(&cur_time, &recv_time);

        //It has been greater than 3 seconds since last message or HB. Connection should be dropped
        //So it can be reset.
        if (last_Rcv >= 3 && con_to_prox == 1)
        {
            FD_CLR(new_cproxy_soc, &readfd);
            close(new_cproxy_soc);
            con_to_prox = 0;
        }

        //It has been >1 second since last HB sent so send one.
        if (last_HB >= 1 && con_to_prox == 1)
        {
            send_hb(new_cproxy_soc, session_id, seqN, ackN);
            gettimeofday(&sent_time, NULL);
        }

        // Got data from cproxy
        if (FD_ISSET(new_cproxy_soc, &readyfd))
        {

            // Get the header
            rv_telnet = recv(new_cproxy_soc, c_buff, 9, 0);
            if (rv_telnet <= 0)
            {
                // printf("new_cproxy_soc recv header val 0\nclosing new_cproxy\nclosing telnet_daem\n\n");fflush;
                FD_CLR(new_cproxy_soc, &readfd);
                FD_CLR(telnet_daem_soc, &readfd);
                close(new_cproxy_soc);
                close(telnet_daem_soc);
                con_to_prox = 0;
                continue;
            }

            // Get header
            long long header = strtoll(c_buff, NULL, 16);
            unsigned long type = (unsigned long)(header >> 33) & 0x1;
            unsigned int p_length = (unsigned int)(header >> 24) & 0x1ff;
            unsigned int rcv_seqN = (unsigned int)(header >> 12) & 0x000fff;
            unsigned int rcv_ackN = (unsigned int)header & 0x000000fff;
            printf("type: %lu\nlength: %d\nrecv_seqN: %d\nrecv_ackN: %d\n", type, p_length, rcv_seqN, rcv_ackN);
            fflush;

            ackN = rcv_seqN;
            memset(c_buff, '\0', sizeof(c_buff));

            // Get the payload
            rv_telnet = recv(new_cproxy_soc, c_buff, p_length, 0);
            gettimeofday(&recv_time, NULL);

            if (type == 1)
            {
                if (send(telnet_daem_soc, c_buff, rv_telnet, 0) <= 0)
                {
                    perror("send to telnet daemon faild");
                    exit(EXIT_FAILURE);
                }
            }
            else if (type == 0)
            {
                unsigned int temp = strtol(c_buff, NULL, 16);

                if (session_id != temp)
                {
                    // printf("New Telnet id (%X) detected closing old deamon connection\n", temp);fflush;
                    session_id = temp;

                    // close telnet daemon and start a new one.
                    FD_CLR(telnet_daem_soc, &readfd);
                    close(telnet_daem_soc);

                    // create client socket to be used pass data between cproxy and server telnet or sproxy.
                    if (((telnet_daem_soc = socket(PF_INET, SOCK_STREAM, 0)) == 0))
                    {
                        perror("server_soc failed.");
                    }

                    if (connect(telnet_daem_soc, (struct sockaddr *)&tnet_daem_soc_addr, sizeof(tnet_daem_soc_addr)) < 0)
                    {
                        perror("Connect failed");
                        exit(EXIT_FAILURE);
                    }

                    FD_SET(telnet_daem_soc, &readfd);
                    if (telnet_daem_soc > sd_max)
                    {
                        sd_max = telnet_daem_soc + 1;
                    }
                }
            }
        }

        //The connection to cproxy's telnet just sen
        if (FD_ISSET(telnet_daem_soc, &readyfd))
        {
            rv_tnet_deam = recv(telnet_daem_soc, s_buff, MAX_LENTH, 0);

            //If < 0 then bad connection, it should be closed.
            if (rv_tnet_deam <= 0)
            {
                FD_CLR(new_cproxy_soc, &readfd);
                FD_CLR(telnet_daem_soc, &readfd);
                close(new_cproxy_soc);
                close(telnet_daem_soc);
                con_to_prox = 0;
            }
            //The connection is good and can be sent on to the telnet connection or be queued to be sent.
            else
            {
                //The connection is good sent right away.
                if (con_to_prox)
                {
                    //If queue->head has more than one message to send and the connection is good, then send all backlogged
                    //messages.
                    while(queue->head != NULL){
                        enqueue(queue, rv_tnet_deam, s_buff, seqN, ackN);
                        seqN++;
                        send_telnet(new_cproxy_soc, queue->head->data, queue->head->data_len, queue->head->seq_num, 0);
                        dequeue(queue);
                        gettimeofday(&sent_time, NULL);
                    }
                //The connection is down, but telnet has data, just enqueue and move on, data will be sent later.
                } else{
                    seqN++;
                    enqueue(queue, rv_tnet_deam, s_buff, seqN, ackN);
                }
            }
        }

        //cproxy is ready to establish a connection on new_cproxy_soc.
        if (FD_ISSET(cproxy_soc, &readyfd))
        {
            // printf("**** New Cproxy connection ****\n");fflush;
            // accept new connection
            new_cproxy_soc = accept(cproxy_soc, (struct sockaddr *)&accepted_soc_addr, (socklen_t *)&accepted_soc_addr_len);
            // printf("new_cproxy_soc = %d\n", new_cproxy_soc);fflush;
            if (new_cproxy_soc < 0)
            {
                perror("Accpet Failed");
                exit(EXIT_FAILURE);
            }

            // add to FD_SET the new connection
            FD_SET(new_cproxy_soc, &readfd);
            if (new_cproxy_soc > sd_max)
            {
                sd_max = new_cproxy_soc + 1;
            }

            // recv hb here
            rv_telnet = recv(new_cproxy_soc, c_buff, 9, 0);
            
            //Parse HB header.
            long long header = strtoll(c_buff, NULL, 16);
            unsigned long type = (unsigned long)(header >> 33) & 0x1;
            unsigned int p_length = (unsigned int)(header >> 24) & 0x1ff;
            unsigned int rcv_seqN = (unsigned int)(header >> 12) & 0x000fff;
            unsigned int rcv_ackN = (unsigned int)header & 0x000000fff;
            ackN = rcv_seqN;
            printf("type: %lu\nlength: %d\nrecv_seqN: %d\nrecv_ackN: %d\n", type, p_length, rcv_seqN, rcv_ackN);
            fflush;
            memset(c_buff, '\0', sizeof(c_buff));
            
            // Get the payload
            rv_telnet = recv(new_cproxy_soc, c_buff, p_length, 0);
            gettimeofday(&recv_time, NULL);

            //Respond with HB.
            send_hb(new_cproxy_soc, session_id, seqN, ackN);
            gettimeofday(&sent_time, NULL);
            con_to_prox = 1;
        }

        memset(c_buff, '\0', sizeof(c_buff));
        memset(s_buff, '\0', sizeof(s_buff));
    }

    return 0;
}


/*---------------------------------------------------------------------
|  Method send_hb()
|
|  Purpose: A method used to send a standardized heartbeat header to the opposite
|           client/server. Used for signaling that a connection between the two
|           daemons is still functional.
|
|
|  Params: int sock: The passed socket to send a HB to.
|   unsigned int id: The session ID generated for the connection.
|          int seqN: The current sequence # to be send.
|          int ackN: The last good acknowledgement recieved.
|
|  Returns: NOP No return value.
*-------------------------------------------------------------------*/
void send_hb(int sock, unsigned int id, int seqN, int ackN)
{
    //Create header by loading it into a long long.
    char hdr_str[9];
    unsigned long long hdr = 0x408000000;
    hdr |= seqN << 12;
    hdr |= ackN;
    sprintf(hdr_str, "%llX", hdr);
    char payload[8];
    sprintf(payload, "%X", id);

    //Send header
    if (send(sock, hdr_str, 9, 0) <= 0)
    {
        perror("HB Header failed to send");
        exit(EXIT_FAILURE);
    }
    //Send Message
    if (send(sock, payload, 8, 0) <= 0)
    {
        perror("HB Payload failed to send");
        exit(EXIT_FAILURE);
    }
    memset(payload, '\0', sizeof(payload));
}

/*---------------------------------------------------------------------
|  Method send_telnet()
|
|  Purpose: A method used to send a standardized heartbeat header and message 
|           to the opposite client/server. Message header data is aggregated into
|           a single long long and send to be parsed. After header is sent,
|           the length section is used to recieve the message. If successfully
|           recieved, an updated ackN will be send back as confirmation in the next
|           message sent.
|
|
|  Params: int sock: The passed socket to send a HB to.
|        char* data: The actual message to be sent.
|      int data_len: The length of the message to be sent.
|          int seqN: The current sequence # to be send.
|          int ackN: The last good acknowledgement recieved.
|
|  Returns: NOP No return value.
*-------------------------------------------------------------------*/
void send_telnet(int sock, char *data, int data_len, int seqN, int ackN)
{
    // Bit manipulation for header
    char hdr_str[9];
    unsigned long long hdr = 0x200000000;
    hdr |= data_len << 24;
    hdr |= seqN << 12;
    hdr |= ackN;
    sprintf(hdr_str, "%llX", hdr);

    if (send(sock, hdr_str, 9, 0) <= 0)
    {
        perror("Telnet header to sproxy failed");
        exit(EXIT_FAILURE);
    }

    if (send(sock, data, data_len, 0) <= 0)
    {
        perror("Telnet data to sproxy failed");
        exit(EXIT_FAILURE);
    }
}

/*---------------------------------------------------------------------
|  Method time_dif()
|
|  Purpose: A method used to send calculate the current difference between various
|           timekeeping structs. The values of these structs are used to generate
|           an integer value which is used to notify if a connection is still valid,
|           or if a heartbeat message should be sent.
|
|
|  Params: struct timeval a: a struct which logs time. The values from tv_sec are
|                            updated to record the last activity for the associated
|                            parameter.
|          struct timeval b: a struct which logs time. The values from tv_sec are
|                            updated to record the last activity for the associated
|                            parameter.
|          NOTE: The raw difference between a and b is used to determine passed time since
|                some signal was received/sent values of 1(HB) and 3(Lost connection) will
|                trigger various events to take place.
|
|  Returns: The integer difference between a and b.
*-------------------------------------------------------------------*/
int time_dif(struct timeval *a, struct timeval *b)
{
    int sec_def = (int)a->tv_sec - b->tv_sec;
    return sec_def;
}

/*---------------------------------------------------------------------
|  Method enqueue()
|
|  Purpose: To add a new packet to the end of a packet queue (pack_queue).
|           This method dynamically allocates memory for a new packet, 
|           sets its properties, and places it at the end of the queue.
|
|  Params:  pack_queue *queue: a pointer to the queue where the packet
|                              will be added.
|           int data_len: the length of the data to be added to the packet.
|           const char *data: the actual data to be added to the packet.
|           int passedSeq: the sequence number for the packet.
|           int passedAck: the acknowledgment number for the packet.
|
|  Returns: NONE. This method does not return a value. The queue is modified
|           in place to include the new packet.
*-------------------------------------------------------------------*/
void enqueue(pack_queue *queue, int data_len, const char *data, int passedSeq, int passedAck)
{
    packet *new_packet = (packet *)malloc(sizeof(packet));
    printf("PassedSeq was %d\n", passedSeq);
    new_packet->data_len = data_len;
    new_packet->seq_num = passedSeq;
    new_packet->ack_num = passedAck;
    memcpy(new_packet->data, data, data_len);
    new_packet->next = NULL;

    printf("seqN is now %d\n", passedSeq);

    if (queue->head == NULL)
    {
        queue->head = new_packet;
    }
    else
    {
        packet *current = queue->head;
        while (current->next != NULL)
        {
            current = current->next;
        }
        current->next = new_packet;
    }
    queue->size++;
}

/*---------------------------------------------------------------------
|  Method dequeue()
|
|  Purpose: To remove a packet from the front of a packet queue (pack_queue).
|           This method checks if the queue is empty before attempting to remove a 
|           packet. If it is not empty, the packet at the front of the queue is 
|           removed and its memory is freed.
|
|  Params:  pack_queue *queue: a pointer to the queue from which the packet
|                              will be removed.
|
|  Returns: NONE. This method does not return a value. The queue is modified
|           in place to exclude the dequeued packet.
*-------------------------------------------------------------------*/
void *dequeue(pack_queue *queue)
{
    if (queue->size == 0 || queue->head == NULL)
    {
        printf("Queue was at 0 and you tried to dequeue\n");
    }
    else
    {
        packet *dequeued_packet = queue->head;
        queue->head = dequeued_packet->next;
        queue->size--;
        free(dequeued_packet);
    }
}