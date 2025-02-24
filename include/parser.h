#include <librdkafka/rdkafka.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <uthash.h>

// Capture and dissect packet in real time
char *parse_packet(char *device_name, char *kafka_addr, char *group_id);

// Set up callback function for send packet to wrap layer
typedef void (*DataCallback)(const char *, int, const char *);
void GetDataCallback(char *data, int length, char *windowKey);
void setDataCallback(DataCallback callback);