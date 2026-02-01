ARG WIRESHARK_VER=4.6.3
ARG PCAP_VER=1.10.6
ARG RDKAFKA_VER=2.13.0
ARG GO_VER=1.25.6
ARG CJSON_VER=1.7.19
ARG CHASH_VER=2.3.0

# =============================================================================
# Stage 1: DLL Builder
# =============================================================================
FROM ubuntu:24.04 AS dll-builder
ARG WIRESHARK_VER
ARG PCAP_VER
ARG RDKAFKA_VER
ARG CJSON_VER
ARG CHASH_VER

RUN sed -i 's@//.*archive.ubuntu.com@//mirrors.aliyun.com@g' /etc/apt/sources.list.d/ubuntu.sources && \
    sed -i 's@//.*security.ubuntu.com@//mirrors.aliyun.com@g' /etc/apt/sources.list.d/ubuntu.sources && \
    sed -i 's@//ports.ubuntu.com@//mirrors.aliyun.com@g' /etc/apt/sources.list.d/ubuntu.sources

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    build-essential gcc-multilib cmake ninja-build wget \
    flex bison doxygen \
    libpcap-dev libglib2.0-dev libssl-dev libc-ares-dev \
    libgcrypt20-dev libspeexdsp-dev libgmp-dev libunbound-dev \
    libxml2-dev libsasl2-dev libzstd-dev libcurl4-openssl-dev ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /opt

# Build Wireshark
RUN wget https://www.wireshark.org/download/src/wireshark-${WIRESHARK_VER}.tar.xz -L --no-check-certificate && \
    tar -xf wireshark-${WIRESHARK_VER}.tar.xz && \
    mv wireshark-${WIRESHARK_VER} wireshark
WORKDIR /opt/wireshark/build
RUN cmake -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_wireshark=OFF \
    -DENABLE_LUA=OFF \
    -DDISABLE_PROTOBUF=ON \
    -DENABLE_DEBUG_INFO=OFF \
    -DENABLE_MAN_PAGES=OFF \
    -DDISABLE_GNUTLS=ON \
    -DENABLE_DOCS=OFF \
    -DENABLE_APPLICATION_BUNDLE=OFF \
    -DCMAKE_INSTALL_PREFIX=/opt/wireshark/build .. && \
    ninja -j$(nproc) && \
    ninja install

# Build Libpcap
WORKDIR /opt
RUN wget http://www.tcpdump.org/release/libpcap-${PCAP_VER}.tar.gz --no-check-certificate && \
    tar -zxvf libpcap-${PCAP_VER}.tar.gz && \
    cd libpcap-${PCAP_VER} && \
    ./configure && \
    make && \
    mv libpcap.so.${PCAP_VER} libpcap.so.1

# Build Librdkafka
WORKDIR /opt
RUN wget https://github.com/confluentinc/librdkafka/archive/refs/tags/v${RDKAFKA_VER}.tar.gz -O librdkafka-${RDKAFKA_VER}.tar.gz && \
    tar -zxvf librdkafka-${RDKAFKA_VER}.tar.gz && \
    cd librdkafka-${RDKAFKA_VER} && \
    mkdir build && cd build && \
    cmake -DENABLE_LZ4_EXT=OFF -DCMAKE_BUILD_TYPE=Release .. && \
    make -j$(nproc) && \
    make install


WORKDIR /opt/third_party
WORKDIR /opt/third_party
RUN wget https://raw.githubusercontent.com/DaveGamble/cJSON/v${CJSON_VER}/cJSON.c && \
    wget https://raw.githubusercontent.com/DaveGamble/cJSON/v${CJSON_VER}/cJSON.h && \
    wget https://raw.githubusercontent.com/troydhanson/uthash/v${CHASH_VER}/src/uthash.h

RUN mkdir -p /gowireshark/libs /gowireshark/include/wireshark /gowireshark/include/third_party

RUN cp -d /opt/wireshark/build/run/lib*.so* /gowireshark/libs/ && \
    cp /opt/libpcap-${PCAP_VER}/libpcap.so.1 /gowireshark/libs/ && \
    ln -sf /gowireshark/libs/libpcap.so.1 /gowireshark/libs/libpcap.so && \
    cp -d /usr/local/lib/librdkafka*.so* /gowireshark/libs/

RUN cp /opt/wireshark/*.h /gowireshark/include/wireshark/ && \
    cp /opt/wireshark/build/*.h /gowireshark/include/wireshark/ && \
    cp -r /opt/wireshark/include/* /gowireshark/include/wireshark/ && \
    cp -r /opt/wireshark/epan /gowireshark/include/wireshark/ && \
    cp -r /opt/wireshark/wiretap /gowireshark/include/wireshark/ && \
    cp -r /opt/wireshark/wsutil /gowireshark/include/wireshark/

RUN cp /opt/libpcap-${PCAP_VER}/*.h /gowireshark/include/ && \
    cp -r /usr/local/include/librdkafka /gowireshark/include/

RUN cp /opt/third_party/* /gowireshark/include/third_party/

RUN rm -rf /opt/*.tar.* /var/tmp/*

# =============================================================================
# Stage 2: Go Builder
# =============================================================================
FROM ubuntu:24.04 AS go-builder

RUN sed -i 's@//.*archive.ubuntu.com@//mirrors.aliyun.com@g' /etc/apt/sources.list.d/ubuntu.sources && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
    golang-go \
    build-essential \
    pkg-config \
    libglib2.0-dev \
    libpcap-dev \
    libssl-dev \
    libzstd-dev \
    libsasl2-dev \
    libxml2-dev \
    libc-ares-dev \
    libcurl4-openssl-dev \
    ca-certificates && \
    rm -rf /var/lib/apt/lists/*

ENV CGO_ENABLED=1 \
    GOPROXY=https://goproxy.cn,direct \
    CGO_CFLAGS="-I/gowireshark/include -I/gowireshark/include/wireshark -I/gowireshark/include/third_party -I/gowireshark/include/wireshark/epan -I/gowireshark/include/wireshark/wiretap -I/gowireshark/include/wireshark/wsutil -I/gowireshark/include/librdkafka" \
    CGO_LDFLAGS="-L/gowireshark/libs -Wl,-rpath,/app/libs -lwiretap -lwsutil -lwireshark -lpcap -lrdkafka -lxml2 -lcares -lcurl -lglib-2.0 -lresolv -lpthread"

COPY --from=dll-builder /gowireshark/libs/ /gowireshark/libs/
COPY --from=dll-builder /gowireshark/include/ /gowireshark/include/

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download
COPY . .

RUN go build -trimpath -ldflags="-s -w" -o /app/pkt_parser ./cmd/main.go

# =============================================================================
# Stage 3: Runtime
# =============================================================================
FROM ubuntu:24.04 AS runtime

ENV TZ=Asia/Shanghai \
    DEBIAN_FRONTEND=noninteractive

RUN sed -i 's@//.*archive.ubuntu.com@//mirrors.aliyun.com@g' /etc/apt/sources.list.d/ubuntu.sources && \
    sed -i 's@//.*security.ubuntu.com@//mirrors.aliyun.com@g' /etc/apt/sources.list.d/ubuntu.sources && \
    sed -i 's@//ports.ubuntu.com@//mirrors.aliyun.com@g' /etc/apt/sources.list.d/ubuntu.sources

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    libpcap0.8 libc-ares2 libglib2.0-0 libgcrypt20 libxml2 openssl \
    libsasl2-2 libzstd1 libcurl4 ca-certificates tzdata && \
    ln -sf /usr/share/zoneinfo/Asia/Shanghai /etc/localtime && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*


COPY --from=go-builder /app/pkt_parser /app/pkt_parser
COPY --from=dll-builder /gowireshark/libs/ /app/libs/

ENV LD_LIBRARY_PATH=/app/libs
WORKDIR /app
ENTRYPOINT ["/app/pkt_parser"]