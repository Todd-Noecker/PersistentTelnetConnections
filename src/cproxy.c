#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sys/select.h>
#include <sys/time.h>
#include <time.h>

#define MAX_LENTH 256

void send_hb(int sock, unsigned int id, int seqN, int ackN);
void send_telnet(int sock, char *data, int data_len, int seqN, int ackN);
int time_dif(struct timeval *a, struct timeval *b);

int seqN = 0;
int ackN = 0;

int main(int argc, char const *argv[])
{
    char *sip = malloc(20);
    char s_buff[MAX_LENTH], c_buff[MAX_LENTH];
    memset(c_buff, '\0', sizeof(c_buff));
    memset(s_buff, '\0', sizeof(s_buff));

    struct sockaddr_in telnet_cproxy_soc_addr, sproxy_soc_addr, accepted_soc_addr;
    struct timeval select_timeout, cur_time, sent_time, recv_time;
    sent_time.tv_sec = 0;
    sent_time.tv_usec = 0;
    recv_time.tv_sec = 0;
    recv_time.tv_usec = 0;
    int accepted_soc_addr_len = sizeof(accepted_soc_addr);
    int telnet_soc, sproxy_soc, new_telnet_soc;
    int con_to_prox = 0;
    unsigned int session_id = 0;
    int select_retval;
    int s_port, c_port;
    int max_fd;
    int rv_telnet, rv_sproxy;
    int sd_max;

    fd_set readfd, readyfd;

    // check arg count
    if (argc != 4)
    {
        printf("Invalid args\t");
        printf("./cproxy <c_port> <sip> <s_port>\n");
        printf("c_port - port client telnet connects to\n");
        printf("sip - ip address of server machine to connect to\n");
        printf("s_port - server port");
        return -1;
    }

    // grab data from argv
    strcpy(sip, argv[2]);
    c_port = atoi(argv[1]);
    s_port = atoi(argv[3]);

    // printf("**** Setup telnet sock to listen ****\n");fflush;
    // create server socket this is between client telnet and cproxy
    if (((telnet_soc = socket(PF_INET, SOCK_STREAM, 0)) == 0))
    {
        perror("server_soc failed.");
    }

    // setup telnet_server_soc_addr
    bzero(&telnet_cproxy_soc_addr, sizeof(telnet_cproxy_soc_addr));

    telnet_cproxy_soc_addr.sin_family = AF_INET;
    telnet_cproxy_soc_addr.sin_addr.s_addr = INADDR_ANY;
    telnet_cproxy_soc_addr.sin_port = htons(c_port);

    // bind and listen to server_soc between cproxy and client telent
    if (bind(telnet_soc, (struct sockaddr *)&telnet_cproxy_soc_addr, sizeof(telnet_cproxy_soc_addr)) < 0)
    {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }
    if (listen(telnet_soc, 5) < 0)
    {
        perror("Listen");
        exit(EXIT_FAILURE);
    }

    // set up file descripter set and add the server socket
    FD_ZERO(&readfd);
    FD_SET(telnet_soc, &readfd);
    sd_max = telnet_soc + 1;

    // accept new connection
    new_telnet_soc = accept(telnet_soc, (struct sockaddr *)&accepted_soc_addr, (socklen_t *)&accepted_soc_addr_len);
    if (new_telnet_soc < 0)
    {
        perror("Accpet Failed");
        exit(EXIT_FAILURE);
    }

    // generate a new random 32 bit session id
    srand(time(NULL));
    session_id = rand() & 0xffffffff;

    // add to FD_SET the new connection
    FD_SET(new_telnet_soc, &readfd);
    if (new_telnet_soc > sd_max)
    {
        sd_max = new_telnet_soc + 1;
    }

    // setup sproxy_soc_addr
    bzero(&sproxy_soc_addr, sizeof(sproxy_soc_addr));

    sproxy_soc_addr.sin_family = AF_INET;
    sproxy_soc_addr.sin_addr.s_addr = inet_addr(sip);
    sproxy_soc_addr.sin_port = htons(s_port);
    free(sip);

    // create client socket to be used pass data between cproxy and server telnet or sproxy.
    if (((sproxy_soc = socket(PF_INET, SOCK_STREAM, 0)) == 0))
    {
        perror("server_soc failed.");
    }

    // connect to sproxy/server telnet
    if (connect(sproxy_soc, (struct sockaddr *)&sproxy_soc_addr, sizeof(sproxy_soc_addr)) < 0)
    {
        perror("Connect failed");
        exit(EXIT_FAILURE);
    }

    // Send first HB
    send_hb(sproxy_soc, session_id, seqN, ackN);
    gettimeofday(&sent_time, NULL);

    // get Sproxy first HB
    rv_sproxy = recv(sproxy_soc, s_buff, 9, 0);
    
    // Parse HB from sproxy.
    long long header = strtoll(s_buff, NULL, 16);
    unsigned long type = (unsigned long)(header >> 33) & 0x1;
    unsigned int p_length = (unsigned int)(header >> 24) & 0x1ff;
    unsigned int rcv_seqN = (unsigned int)(header >> 12) & 0x000fff;
    unsigned int rcv_ackN = (unsigned int)header & 0x000000fff;

    seqN = rcv_seqN;
    memset(s_buff, '\0', sizeof(s_buff));
    
    // get payload
    rv_sproxy = recv(sproxy_soc, s_buff, p_length, 0);
    gettimeofday(&recv_time, NULL);

    if (type == 0)
    {
        unsigned int temp = strtol(s_buff, NULL, 16);
    }

    memset(s_buff, '\0', sizeof(s_buff));
    FD_SET(sproxy_soc, &readfd);
    if (sproxy_soc > sd_max)
    {
        sd_max = sproxy_soc + 1;
    }

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
            // printf("Handle Disconnect Closing sproxy_soc: %d\n", last_Rcv);fflush;
            FD_CLR(sproxy_soc, &readfd);
            close(sproxy_soc);
            con_to_prox = 0;

            if (((sproxy_soc = socket(PF_INET, SOCK_STREAM, 0)) == 0))
            {
                perror("server_soc failed.");
            }
            int con_retval = -1;
            do
            {
                con_retval = connect(sproxy_soc, (struct sockaddr *)&sproxy_soc_addr, sizeof(sproxy_soc_addr));
            } while (con_retval < 0);

            // Add reconneded sproxy sock to FD_SET
            FD_SET(sproxy_soc, &readfd);
            if (sproxy_soc >= sd_max)
            {
                sd_max = sproxy_soc + 1;
            }
            // printf("Connected Id: %X\n\n", session_id);fflush;
            con_to_prox = 1;
            send_hb(sproxy_soc, session_id, seqN, 0);
            gettimeofday(&sent_time, NULL);

            // get Sproxy first HB
            rv_sproxy = recv(sproxy_soc, s_buff, 9, 0);
            // printf("recv hdr str:   %s\n", s_buff);
            long long header = strtoll(s_buff, NULL, 16);
            // printf("header long:    %llX\n", header);
            unsigned long type = (unsigned long)(header >> 33) & 0x1;
            unsigned int p_length = (unsigned int)(header >> 24) & 0x1ff;
            unsigned int rcv_seqN = (unsigned int)(header >> 12) & 0x000fff;
            unsigned int rcv_ackN = (unsigned int)header & 0x000000fff;

            ackN = rcv_seqN + 1;
            // printf("type: %lu\nlength: %d\nrecv_seqN: %d\nrecv_ackN: %d\n", type, p_length, rcv_seqN, rcv_ackN);fflush;
            memset(s_buff, '\0', sizeof(s_buff));
            // get payload
            rv_sproxy = recv(sproxy_soc, s_buff, p_length, 0);
            gettimeofday(&recv_time, NULL);

            if (type == 0)
            {
                unsigned int temp = strtol(s_buff, NULL, 16);
                // printf("Got First Sproxy HB: %X\n\n", temp);fflush;
            }

            memset(s_buff, '\0', sizeof(s_buff));
        }

        //It has been greater than 1 second since last HB sent, so send one.
        if (last_HB >= 1 && con_to_prox == 1)
        {
            // printf("Timeout HB: %d\n", last_HB);fflush;
            send_hb(sproxy_soc, session_id, seqN, 0);
            gettimeofday(&sent_time, NULL);
        }

        // data is comming in from sproxy
        if (FD_ISSET(sproxy_soc, &readyfd))
        {
            // printf("Got data from Sproxy\n");
            // get header
            rv_sproxy = recv(sproxy_soc, s_buff, 9, 0);
            // printf("recv hdr str:   %s\n", s_buff);
            long long header = strtoll(s_buff, NULL, 16);
            unsigned long type = (unsigned long)(header >> 33) & 0x1;
            unsigned int p_length = (unsigned int)(header >> 24) & 0x1ff;
            unsigned int rcv_seqN = (unsigned int)(header >> 12) & 0x000fff;
            unsigned int rcv_ackN = (unsigned int)header & 0x000000fff;
            seqN = rcv_seqN;
            if (type == 1)
            {
                printf("Got data from Sproxy\n");
                fflush;
                printf("recv hdr str:   %s\n", s_buff);
                printf("type: %lu\nlength: %d\nrecv_seqN: %d\nrecv_ackN: %d\n", type, p_length, rcv_seqN, rcv_ackN);
                fflush;
                printf("Connect status : %d\n", con_to_prox);
                fflush;
            }

            memset(s_buff, '\0', sizeof(s_buff));
            // get payload
            rv_sproxy = recv(sproxy_soc, s_buff, p_length, 0);
            gettimeofday(&recv_time, NULL);

            //Connection returned <=0 indicating an error.
            if (rv_sproxy <= 0)
            {
                FD_CLR(new_telnet_soc, &readfd);
                FD_CLR(sproxy_soc, &readfd);
                close(new_telnet_soc);
                close(sproxy_soc);
                con_to_prox = 0;
            }
            if (type == 1)
            {
                // send to telnet
                if (send(new_telnet_soc, s_buff, rv_sproxy, 0) <= 0)
                {
                    perror("send to telnet faild");
                    exit(EXIT_FAILURE);
                }
            }
            //Got a HB
            else if (type == 0)
            {
                unsigned int temp = strtol(s_buff, NULL, 16);
            }
        }

        //Got a message from client telnet, so pass it on.
        if (FD_ISSET(new_telnet_soc, &readyfd))
        {
            rv_telnet = recv(new_telnet_soc, c_buff, MAX_LENTH, 0);
            //Bad connection, connection should be closed and await reset.
            if (rv_telnet <= 0)
            {
                FD_CLR(new_telnet_soc, &readfd);
                FD_CLR(sproxy_soc, &readfd);
                close(new_telnet_soc);
                close(sproxy_soc);
                con_to_prox = 0;
            }
            //Connection is good so pass the data on to sproxy.
            else
            {
                // send telnet to sproxy
                send_telnet(sproxy_soc, c_buff, rv_telnet, seqN, 0);
                gettimeofday(&sent_time, NULL);

            }
        }

        if (FD_ISSET(telnet_soc, &readyfd))
        {
            // accept new connection
            new_telnet_soc = accept(telnet_soc, (struct sockaddr *)&accepted_soc_addr, (socklen_t *)&accepted_soc_addr_len);
            if (new_telnet_soc < 0)
            {
                perror("Accpet Failed");
                exit(EXIT_FAILURE);
            }

            // generate a new random 32 bit session id
            srand(time(NULL));
            session_id = rand() & 0xffffffff;

            // add to FD_SET the new connection
            FD_SET(new_telnet_soc, &readfd);
            if (new_telnet_soc > sd_max)
            {
                sd_max = new_telnet_soc + 1;
            }

            // create client socket to be used pass data between cproxy and server telnet or sproxy.
            if (((sproxy_soc = socket(PF_INET, SOCK_STREAM, 0)) == 0))
            {
                perror("server_soc failed.");
            }

            // connect to sproxy/server telnet
            if (connect(sproxy_soc, (struct sockaddr *)&sproxy_soc_addr, sizeof(sproxy_soc_addr)) < 0)
            {
                perror("Connect failed");
                exit(EXIT_FAILURE);
            }
            // Send first HB
            send_hb(sproxy_soc, session_id, seqN, 0);
            gettimeofday(&sent_time, NULL);

            FD_SET(sproxy_soc, &readfd);
            if (sproxy_soc > sd_max)
            {
                sd_max = sproxy_soc + 1;
            }

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
    // Create header by loading it into a long long.
    char hdr_str[9];
    unsigned long long hdr = 0x408000000;
    hdr |= seqN << 12;
    hdr |= ackN;
    sprintf(hdr_str, "%llX", hdr);
    char payload[8];
    sprintf(payload, "%X", id);

    //Send header.
    if (send(sock, hdr_str, 9, 0) <= 0)
    {
        perror("HB Header failed to send");
        exit(EXIT_FAILURE);
    }
    //Send message.
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