#include <librdkafka/rdkafka.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <uthash.h>

// judge is json empty
bool is_empty_json(const char *json_str);

// Capture and dissect packet in real time
char *parse_packet(char *device_name, char *kafka_addr, char *options);

// Set up callback function for send packet to wrap layer
typedef void (*DataCallback)(const char *, int, const char *, const char *);
void GetDataCallback(char *data, int length, char *device_name,
                     char *windowKey);
void setDataCallback(DataCallback callback);