#include <cJSON.h>
#include <cfile.h>
#include <epan/charsets.h>
#include <epan/column.h>
#include <epan/epan.h>
#include <epan/epan_dissect.h>
#include <epan/frame_data.h>
#include <epan/frame_data_sequence.h>
#include <epan/prefs.h>
#include <epan/print.h>
#include <epan/print_stream.h>
#include <epan/tap.h>
#include <epan/timestamp.h>
#include <epan/tvbuff.h>
#include <frame_tvbuff.h>
#include <pcap/bpf.h>
#include <pcap/pcap.h>
#include <stdio.h>
#include <wiretap/wtap-int.h>
#include <wiretap/wtap.h>
#include <wsutil/json_dumper.h>
#include <wsutil/nstime.h>
#include <wsutil/privileges.h>

// Init policies、wtap mod、epan mod
bool init_env();

void get_json_proto_tree(output_fields_t *fields,
                         print_dissections_e print_dissections,
                         gboolean print_hex, gchar **protocolfilter,
                         pf_flags protocolfilter_flags, epan_dissect_t *edt,
                         column_info *cinfo,
                         proto_node_children_grouper_func node_children_grouper,
                         json_dumper *dumper);
