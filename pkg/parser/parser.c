#include <lib.h>
#include <parser.h>

// 1. 添加全局控制变量
static volatile int g_keep_running = 1;

// 2. 暴露停止函数
void stop_parser_loop() {
    g_keep_running = 0;
}

// device_content Contains the information needed for each device
typedef struct device_content {
    char *device;
    capture_file *cf_live;
    frame_data prev_dis_frame;
    frame_data prev_cap_frame;
    wtap_rec rec;
    epan_dissect_t edt;
    rd_kafka_t *kafka_consumer;
    rd_kafka_topic_partition_list_t *kafka_topics;
    GString *json_buffer;  // 复用的 buffer
} device_content;

struct device_map {
    char *device_name;
    device_content content;
    UT_hash_handle hh;
};

// global map to restore device info
struct device_map *devices = NULL;

char *add_device(char *device_name);
struct device_map *find_device(char *device_name);

void cap_file_init(capture_file *cf);
char *init_cf_live(capture_file *cf_live);
void close_cf_live(capture_file *cf_live);

static bool prepare_data(wtap_rec *rec, const struct pcap_pkthdr *pkthdr);
static bool send_data_to_wrap(struct device_map *device, const char *window_key);
void before_callback_init(struct device_map *device);

void process_packet_callback(u_char *arg, const struct pcap_pkthdr *pkthdr, const u_char *packet);

// Set up callback function for send packet to Go
static DataCallback dataCallback;
void setDataCallback(DataCallback callback) {
    dataCallback = callback;
}

bool init_kafka_consumer(struct device_map *device, const char *brokers, const char *source_topic,
                         const char *group_id) {
    char errstr[512];

    // 创建 Kafka 配置
    rd_kafka_conf_t *conf = rd_kafka_conf_new();

    // 设置 Broker 地址
    if (rd_kafka_conf_set(conf, "bootstrap.servers", brokers, errstr, sizeof(errstr))) {
        fprintf(stderr, "Failed to set brokers: %s\n", errstr);
        rd_kafka_conf_destroy(conf);  // 失败记得释放
        return false;
    }

    // 设置消费者组
    if (rd_kafka_conf_set(conf, "group.id", group_id, errstr, sizeof(errstr))) {
        fprintf(stderr, "Failed to set group.id: %s\n", errstr);
        rd_kafka_conf_destroy(conf);
        return false;
    }

    // 设置分区分配策略
    if (rd_kafka_conf_set(conf, "partition.assignment.strategy", "roundrobin", errstr,
                          sizeof(errstr))) {
        fprintf(stderr, "Failed to set partition.assignment.strategy: %s\n", errstr);
        return false;
    }

    // 增加每次从 Broker 拉取的最小字节数，减少小包网络交互
    rd_kafka_conf_set(conf, "fetch.min.bytes", "100000", errstr, sizeof(errstr));

    // 稍微增加等待时间以凑够 batch (例如 10ms)
    rd_kafka_conf_set(conf, "fetch.wait.max.ms", "10", errstr, sizeof(errstr));

    // 增加 socket 接收缓冲区
    rd_kafka_conf_set(conf, "socket.receive.buffer.bytes", "1048576", errstr, sizeof(errstr));

    rd_kafka_conf_set(conf, "auto.offset.reset", "earliest", errstr, sizeof(errstr));

    // 创建 Kafka 消费者
    device->content.kafka_consumer = rd_kafka_new(RD_KAFKA_CONSUMER, conf, errstr, sizeof(errstr));
    if (!device->content.kafka_consumer) {
        fprintf(stderr, "Failed to create consumer: %s\n", errstr);
        rd_kafka_conf_destroy(conf);
        return false;
    }

    // 订阅主题
    device->content.kafka_topics = rd_kafka_topic_partition_list_new(1);
    rd_kafka_topic_partition_list_add(device->content.kafka_topics, source_topic,
                                      RD_KAFKA_PARTITION_UA);

    if (rd_kafka_subscribe(device->content.kafka_consumer, device->content.kafka_topics)) {
        fprintf(stderr, "Failed to subscribe\n");
        return false;
    }

    return true;
}

/*
PART1. Use uthash to implement the logic related to the map of the device
*/

char *add_device(char *device_name) {
    char *err_msg;
    struct device_map *s;
    capture_file *cf_tmp;

    HASH_FIND_STR(devices, device_name, s);
    if (s == NULL) {
        s = (struct device_map *)malloc(sizeof *s);
        memset(s, 0, sizeof(struct device_map));

        cf_tmp = (capture_file *)malloc(sizeof *cf_tmp);
        cap_file_init(cf_tmp);

        s->device_name = device_name;
        s->content.cf_live = cf_tmp;

        // init capture_file
        err_msg = init_cf_live(cf_tmp);
        if (err_msg != NULL) {
            if (strlen(err_msg) != 0) {
                close_cf_live(cf_tmp);
                free(cf_tmp);
                free(s);
                return "Add device failed: fail to init cf_live";
            }
        }

        HASH_ADD_KEYPTR(hh, devices, s->device_name, strlen(s->device_name), s);
        return "";
    } else {
        return "The device is in use";
    }
}

struct device_map *find_device(char *device_name) {
    struct device_map *s;

    HASH_FIND_STR(devices, device_name, s);
    return s;
}

#define SNAP_LEN 65535
#define MAX_BUFFER_SIZE 65536

void cap_file_init(capture_file *cf) {
    /* Initialize the capture file struct */
    memset(cf, 0, sizeof(capture_file));
}

// init cf_live
char *init_cf_live(capture_file *cf_live) {
    /* Create new epan session for dissection. */
    epan_free(cf_live->epan);

    cf_live->provider.wth = NULL;
    cf_live->f_datalen = 0; /* not used, but set it anyway */
    /* Indicate whether it's a permanent or temporary file. */
    cf_live->is_tempfile = FALSE;

    /* No user changes yet. */
    cf_live->unsaved_changes = FALSE;
    cf_live->cd_t = WTAP_FILE_TYPE_SUBTYPE_UNKNOWN;
    cf_live->open_type = WTAP_TYPE_AUTO;
    cf_live->count = 0;
    cf_live->drops_known = FALSE;
    cf_live->drops = 0;
    cf_live->snap = 0;
    cf_live->provider.frames = NULL;
    nstime_set_zero(&cf_live->elapsed_time);
    cf_live->provider.ref = NULL;
    cf_live->provider.prev_dis = NULL;
    cf_live->provider.prev_cap = NULL;

    static const struct packet_provider_funcs funcs = {
        cap_file_provider_get_frame_ts,
        cap_file_provider_get_interface_name,
        cap_file_provider_get_interface_description,
        NULL,
        NULL,
        NULL,
        NULL,
    };

    cf_live->epan = epan_new(&cf_live->provider, &funcs);

    e_prefs *prefs_p;
    prefs_p = epan_load_settings();
    build_column_format_array(&cf_live->cinfo, prefs_p->num_cols, TRUE);

    return "";
}

/**
 * Clean the capture file struct.
 */
void close_cf_live(capture_file *cf_live) {
    cf_live->stop_flag = FALSE;
    if (cf_live->provider.wth) {
        wtap_close(cf_live->provider.wth);
        cf_live->provider.wth = NULL;
    }

    /* We have no file open... */
    if (cf_live->filename != NULL) {
        g_free(cf_live->filename);
        cf_live->filename = NULL;
    }

    /* ...which means we have no changes to that file to save. */
    cf_live->unsaved_changes = FALSE;

    /* no open_routine type */
    cf_live->open_type = WTAP_TYPE_AUTO;

    /* Clean up the record metadata. */
    wtap_rec_cleanup(&cf_live->rec);

    cf_live->rfcode = NULL;
    if (cf_live->provider.frames != NULL) {
        free_frame_data_sequence(cf_live->provider.frames);
        cf_live->provider.frames = NULL;
    }
    if (cf_live->provider.frames_modified_blocks) {
        g_tree_destroy(cf_live->provider.frames_modified_blocks);
        cf_live->provider.frames_modified_blocks = NULL;
    }

    /* No frames, no frame selected, no field in that frame selected. */
    cf_live->count = 0;
    cf_live->current_frame = NULL;
    cf_live->finfo_selected = NULL;

    /* No frame link-layer types, either. */
    if (cf_live->linktypes != NULL) {
        g_array_free(cf_live->linktypes, TRUE);
        cf_live->linktypes = NULL;
    }

    cf_live->f_datalen = 0;
    nstime_set_zero(&cf_live->elapsed_time);

    epan_free(cf_live->epan);
    cf_live->epan = NULL;

    /* We have no file open. */
    cf_live->state = FILE_CLOSED;
}

void before_callback_init(struct device_map *device) {
    epan_dissect_init(&device->content.edt, device->content.cf_live->epan, TRUE, TRUE);
    wtap_rec_init(&device->content.rec, 1514);
    device->content.json_buffer = g_string_new(NULL);
    return;
}

static bool prepare_data(wtap_rec *rec, const struct pcap_pkthdr *pkthdr) {
    if (!rec || !pkthdr) {
        printf("Error: rec or pkthdr is NULL\n");
        return false;
    }

    // 初始化 wtap_rec
    rec->rec_type = REC_TYPE_PACKET;
    rec->presence_flags = WTAP_HAS_TS | WTAP_HAS_CAP_LEN;

    // 设置时间戳
    rec->ts.secs = pkthdr->ts.tv_sec;
    rec->ts.nsecs = pkthdr->ts.tv_usec * 1000;

    // 设置数据包长度
    rec->rec_header.packet_header.caplen = pkthdr->caplen;
    rec->rec_header.packet_header.len = pkthdr->len;
    rec->rec_header.packet_header.pkt_encap = WTAP_ENCAP_ETHERNET;

    // 检查数据包长度是否有效
    if (rec->rec_header.packet_header.len == 0) {
        printf("Error: Packet length is 0\n");
        return false;
    }

    if (pkthdr->caplen > WTAP_MAX_PACKET_SIZE_STANDARD) {
        printf("Error: Packet length exceeds maximum size\n");
        return false;
    }

    return true;
}

// 将解析后的 JSON 发送到 Kafka
static bool send_data_to_wrap(struct device_map *device, const char *window_key) {
    json_dumper dumper = {};
    bool success = false;

    // 复用 buffer：重置长度为0，但不释放底层内存
    g_string_truncate(device->content.json_buffer, 0);

    dumper.output_string = device->content.json_buffer;

    get_json_proto_tree(NULL, print_dissections_expanded, TRUE, NULL, PF_INCLUDE_CHILDREN,
                        &device->content.edt, &device->content.cf_live->cinfo,
                        proto_node_group_children_by_json_key, &dumper);

    if (json_dumper_finish(&dumper)) {
        // 直接使用 buffer->str，去除 g_strdup 的拷贝开销
        if (dataCallback != NULL) {
            // Go 端如果是 C.GoString 会产生一次拷贝，这里 C 端不需要额外拷贝
            dataCallback(device->content.json_buffer->str, device->content.json_buffer->len,
                         (char *)window_key);  // 去除 const 强转，如果 callback 定义允许
            success = true;
        }
    }

    return success;
}

static bool process_packet_from_kafka(struct device_map *device, const unsigned char *packet,
                                      int len, const char *window_key) {
    if (!device || !device->content.cf_live) return false;

    wtap_rec rec;
    wtap_rec_init(&rec, 1514);
    rec.rec_type = REC_TYPE_PACKET;
    rec.presence_flags = WTAP_HAS_TS | WTAP_HAS_CAP_LEN;
    rec.ts.secs = time(NULL);
    rec.rec_header.packet_header.caplen = len;
    rec.rec_header.packet_header.len = len;
    rec.rec_header.packet_header.pkt_encap = WTAP_ENCAP_ETHERNET;

    frame_data fd;
    epan_dissect_t *edt;
    guint32 cum_bytes = 0;

    frame_data_init(&fd, ++device->content.cf_live->count, &rec, 0, cum_bytes);
    edt = epan_dissect_new(device->content.cf_live->epan, TRUE, TRUE);

    device->content.cf_live->provider.ref = &fd;

    epan_dissect_run_with_taps(edt, device->content.cf_live->cd_t, &rec, &fd, NULL);

    bool ret = send_data_to_wrap(device, window_key);

    device->content.cf_live->provider.ref = NULL;
    epan_dissect_free(edt);
    frame_data_destroy(&fd);
    wtap_rec_cleanup(&rec);

    return ret;
}

// Kafka 消费循环
void kafka_capture_loop(struct device_map *device) {
    while (g_keep_running) {
        rd_kafka_message_t *msg = rd_kafka_consumer_poll(device->content.kafka_consumer, 200);
        if (!msg) {
            continue;
        }

        if (msg->err) {
            fprintf(stderr, "Consumer error: %s\n", rd_kafka_message_errstr(msg));
            rd_kafka_message_destroy(msg);
            continue;
        }

        // 直接获取 Kafka 消息的二进制数据
        const unsigned char *packet = (const unsigned char *)msg->payload;
        int len = msg->len;

        // 获取 window_key
        char window_key[64] = {0};  // 预留足够空间
        if (msg->key && msg->key_len > 0) {
            int copy_len =
                msg->key_len < sizeof(window_key) - 1 ? msg->key_len : sizeof(window_key) - 1;
            memcpy(window_key, msg->key, copy_len);
            window_key[copy_len] = '\0';  // 确保 C 字符串结尾
        } else {
            strcpy(window_key, "UNKNOWN");
        }

        // 处理数据包
        if (!process_packet_from_kafka(device, packet, len, window_key)) {
            printf("Error: Failed to process packet from Kafka\n");
        }

        // 释放 Kafka 消息
        rd_kafka_message_destroy(msg);
    }
}

char *parse_packet(char *device_name, char *source_topic, char *kafka_addr, char *group_id) {
    char *err_msg = add_device(device_name);
    if (err_msg && strlen(err_msg) != 0) {
        return err_msg;
    }

    struct device_map *device = find_device(device_name);
    if (!device) {
        return "The device is not in the global map";
    }

    printf("Kafka customer init!\n");

    // 传入 device 指针
    if (!init_kafka_consumer(device, kafka_addr, source_topic, group_id)) {
        return "Failed to initialize Kafka consumer";
    }

    printf("Kafka customer start!\n");

    // 启动 Kafka 消费循环
    before_callback_init(device);
    kafka_capture_loop(device);

    return "";
}