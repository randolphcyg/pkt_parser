package pkt_parser

import (
	"bufio"
	"crypto/md5"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"
)

var (
	//go:embed mime_types.txt
	mimeTypesFile embed.FS

	validExtensions = make(map[string]bool)
	mu              sync.RWMutex

	genFilenameLock sync.Mutex

	ExtractFileDir = "" // extract file save dir
)

func init() {
	data, err := mimeTypesFile.ReadFile("mime_types.txt")
	if err != nil {
		slog.Warn("Error:", "Failed to read embedded file", err)
		return
	}

	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) == 2 {
			ext, typ := parts[0], parts[1]
			// Add to mime library
			err := mime.AddExtensionType(ext, typ)
			if err != nil {
				slog.Warn("Error:", "Failed to add extension type", err)
			}
			// Add to valid extensions map
			mu.Lock()
			validExtensions[ext] = true
			mu.Unlock()
		} else {
			slog.Warn("Error:", "Invalid line in mime types file", line)
		}
	}

	if err := scanner.Err(); err != nil {
		slog.Warn("Error:", "Error reading mime types file", err)
	}
}

// IsValidFileExtension checks if a file has a valid extension
func IsValidFileExtension(filename string) bool {
	ext := strings.ToLower(strings.TrimSpace(filepath.Ext(filename)))
	mu.RLock()
	defer mu.RUnlock()
	return validExtensions[ext]
}

// GenerateUniqueFilenameWithIncrement if file exist, add auto-increment num
func GenerateUniqueFilenameWithIncrement(filename string) string {
	genFilenameLock.Lock()
	defer genFilenameLock.Unlock()

	ext := filepath.Ext(filename)
	base := strings.TrimSuffix(filename, ext)
	counter := 1

	for {
		path := filepath.Join(ExtractFileDir, filename)
		if !IsFileExist(path) {
			break
		}
		filename = fmt.Sprintf("%s(%d)%s", base, counter, ext)
		counter++
	}

	return filepath.Join(ExtractFileDir, filename)
}

// UrlStringDecode Decode URL-encoded strings into raw text
func UrlStringDecode(encoded string) (string, error) {
	return url.QueryUnescape(encoded)
}

func ExtractHttpFilename(http *Http) (string, error) {
	if http.ResponseLine == nil || http.FileData == "" {
		return "", errors.New("no file data")
	}

	if http.ResponseCode == "404" || http.ResponseCode == "301" {
		return "", errors.New("ignore 404 or 301")
	}

	filename := "tmp"
	includeFilename := false

	// Content-Disposition
	for _, line := range *http.ResponseLine {
		if strings.Contains(strings.ToLower(line), "filename=") {
			reg := regexp.MustCompile(`(?i)filename="?([^"]+)"?`)
			if match := reg.FindStringSubmatch(line); len(match) > 1 {
				filename = match[1]
				includeFilename = true
				break
			}
		} else if strings.Contains(strings.ToLower(line), "filename*=utf-8''") {
			reg := regexp.MustCompile(`(?i)filename\*=utf-8''([^;,\r\n]+)`)
			if match := reg.FindStringSubmatch(line); len(match) > 1 {
				if decoded, err := UrlStringDecode(match[1]); err == nil {
					filename = decoded
					includeFilename = true
					break
				} else {
					slog.Warn("Error:", "Failed to decode URL-encoded filename", err)
				}
			}
		}
	}

	// URL
	if !includeFilename {
		p := http.ResponseUrl
		if p == "" {
			p = http.RequestUri
		}
		filename = filepath.Base(p)
		filename, _ = url.QueryUnescape(strings.Split(filename, "?")[0])
	}

	// check filename validation
	if filename == "" || filename == "/" || !IsValidFileExtension(filename) {
		filename = "tmp"
	}

	// speculate on file types and generate file extensions
	if filepath.Ext(filename) == "" && http.ContentType != "" {
		if http.ContentType != "" {
			extensions, _ := mime.ExtensionsByType(http.ContentType)
			if len(extensions) > 0 {
				filename += extensions[0]
			}
		}
	}

	// Make sure the filename is unique and add an extension
	path := filepath.Join(ExtractFileDir, filename)
	if IsFileExist(path) {
		path = GenerateUniqueFilenameWithIncrement(filename)
	}

	return path, nil
}

func ExtractHttpFile(httpList []*Http) ([]string, error) {
	paths := make([]string, 0)
	for _, http := range httpList {
		if http == nil {
			continue
		}

		path, err := ExtractHttpFilename(http)
		if err != nil {
			continue
		}

		file, err := os.Create(path)
		if err != nil {
			slog.Warn("Error:", "Failed to create file", err)
			continue
		}
		defer file.Close()

		decoder := strings.NewReader(strings.ReplaceAll(http.FileData, ":", ""))
		buffer := make([]byte, 1024*1024) // 1MB buffer

		for {
			n, err := decoder.Read(buffer)
			if err != nil && err != io.EOF {
				slog.Warn("Error:", "Error reading file", err)
				break
			}

			if n == 0 {
				break
			}

			decodedData := make([]byte, hex.DecodedLen(n))
			_, decodeErr := hex.Decode(decodedData, buffer[:n])
			if decodeErr != nil {
				slog.Warn("Error:", "Error decoding file", err)
				break
			}

			if _, writeErr := file.Write(decodedData); writeErr != nil {
				slog.Warn("Error:", "Error writing file", err)
				break
			}
		}
		paths = append(paths, path)
	}

	return paths, nil
}

// FTPCommandTree 表示 FTP 命令的字段
type FTPCommandTree struct {
	Command string `json:"ftp.command"`     // FTP 命令（如 USER, PASS, LIST 等）
	Arg     string `json:"ftp.command.arg"` // 命令参数
}

// FTPResponseTree 表示 FTP 响应的字段
type FTPResponseTree struct {
	Code    string `json:"ftp.response.code"`    // 响应代码（如 200, 220, 331 等）
	Message string `json:"ftp.response.message"` // 响应消息
}

// FTPDataTree 表示 FTP 数据传输的字段
type FTPDataTree struct {
	FileSize     int    `json:"ftp.data.file_size"`     // 文件大小
	FileName     string `json:"ftp.data.file_name"`     // 文件名称
	FileData     []byte `json:"ftp.data.file_data"`     // 文件内容
	DownloadTime string `json:"ftp.data.download_time"` // 文件下载时间
}

// FTPLayer 表示 FTP 协议层
type FTPLayer struct {
	PacketLength string          `json:"ftp.packet_length"` // 数据包长度
	PacketNumber string          `json:"ftp.packet_number"` // 数据包序号
	Command      FTPCommandTree  `json:"ftp.command_tree"`  // FTP 命令
	Response     FTPResponseTree `json:"ftp.response_tree"` // FTP 响应
	Data         FTPDataTree     `json:"ftp.data_tree"`     // FTP 数据传输

	// 会话信息
	ClientAddress string `json:"ftp.client_address"` // 客户端地址
	ServerAddress string `json:"ftp.server_address"` // 服务端地址

	// 工作模式
	Mode                  string `json:"ftp.mode"`                    // 工作模式（ACTIVE/PASV）
	ModeRequestConfirmed  bool   `json:"ftp.mode_request_confirmed"`  // 工作模式请求确认
	ModeResponseConfirmed bool   `json:"ftp.mode_response_confirmed"` // 工作模式响应确认
	TransPort             int    `json:"ftp.trans_port"`              // 数据传输端口

	// 文件传输
	FileRequestConfirmed  bool   `json:"ftp.file_request_confirmed"`  // 文件请求确认
	FileResponseConfirmed bool   `json:"ftp.file_response_confirmed"` // 文件响应确认
	FileRequestAck        uint32 `json:"ftp.file_request_ack"`        // 文件请求 ACK

	// 数据连接通道
	DataClientPort   int    `json:"ftp.data_client_port"`   // 数据通道：客户端端口
	DataServerPort   int    `json:"ftp.data_server_port"`   // 数据通道：服务端端口
	FirstSynSeq      uint32 `json:"ftp.first_syn_seq"`      // 第一次握手序列号
	SecondSynAckSeq  uint32 `json:"ftp.second_syn_ack_seq"` // 第二次握手序列号
	FirstHandshaked  bool   `json:"ftp.first_handshaked"`   // 第一次握手完成
	SecondHandshaked bool   `json:"ftp.second_handshaked"`  // 第二次握手完成
	ThirdHandshaked  bool   `json:"ftp.third_handshaked"`   // 第三次握手完成

	// 控制通道
	CtrlClientPort int    `json:"ftp.ctrl_client_port"` // 控制通道：客户端端口
	CtrlServerPort int    `json:"ftp.ctrl_server_port"` // 控制通道：服务端端口
	RequestAck     uint32 `json:"ftp.request_ack"`      // 请求 ACK

	// 其他
	LastTime         int64  `json:"ftp.last_time"`      // 最近一次报文刷新时间
	FtpDataConfirmed bool   `json:"ftp.data_confirmed"` // 数据传输确认
	FtpDataSize      int    `json:"ftp.data_size"`      // 实际解析出来的文件大小
	FtpRespNum       uint32 `json:"ftp.resp_num"`       // 文件分包数量
}

// Parse FTP
func (p *FTPLayer) Parse(layers Layers) (any, error) {
	src, ok := layers["ftp"]
	if !ok {
		return nil, errors.Wrap(ErrLayerNotFound, "ftp")
	}

	type tmpFTPLayer struct {
		PacketLength string `json:"ftp.packet_length"`
		PacketNumber string `json:"ftp.packet_number"`

		Command struct {
			Command string `json:"ftp.command"`
			Arg     string `json:"ftp.command.arg"`
		} `json:"ftp.command_tree"`

		Response struct {
			Code    string `json:"ftp.response.code"`
			Message string `json:"ftp.response.message"`
		} `json:"ftp.response_tree"`

		Data struct {
			FileSize     string `json:"ftp.data.file_size"`
			FileName     string `json:"ftp.data.file_name"`
			FileData     string `json:"ftp.data.file_data"`
			DownloadTime string `json:"ftp.data.download_time"`
		} `json:"ftp.data_tree"`

		ClientAddress string `json:"ftp.client_address"`
		ServerAddress string `json:"ftp.server_address"`

		Mode                  string `json:"ftp.mode"`
		ModeRequestConfirmed  string `json:"ftp.mode_request_confirmed"`
		ModeResponseConfirmed string `json:"ftp.mode_response_confirmed"`
		TransPort             string `json:"ftp.trans_port"`

		FileRequestConfirmed  string `json:"ftp.file_request_confirmed"`
		FileResponseConfirmed string `json:"ftp.file_response_confirmed"`
		FileRequestAck        string `json:"ftp.file_request_ack"`

		DataClientPort   string `json:"ftp.data_client_port"`
		DataServerPort   string `json:"ftp.data_server_port"`
		FirstSynSeq      string `json:"ftp.first_syn_seq"`
		SecondSynAckSeq  string `json:"ftp.second_syn_ack_seq"`
		FirstHandshaked  string `json:"ftp.first_handshaked"`
		SecondHandshaked string `json:"ftp.second_handshaked"`
		ThirdHandshaked  string `json:"ftp.third_handshaked"`

		CtrlClientPort string `json:"ftp.ctrl_client_port"`
		CtrlServerPort string `json:"ftp.ctrl_server_port"`
		RequestAck     string `json:"ftp.request_ack"`

		LastTime         string `json:"ftp.last_time"`
		FtpDataConfirmed string `json:"ftp.data_confirmed"`
		FtpDataSize      string `json:"ftp.data_size"`
		FtpRespNum       string `json:"ftp.resp_num"`
	}

	var tmp tmpFTPLayer
	jsonData, err := json.Marshal(src)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(jsonData, &tmp)
	if err != nil {
		return nil, ErrParseFrame
	}

	p.PacketLength = tmp.PacketLength
	p.PacketNumber = tmp.PacketNumber

	p.Command.Command = tmp.Command.Command
	p.Command.Arg = tmp.Command.Arg

	p.Response.Code = tmp.Response.Code
	p.Response.Message = tmp.Response.Message

	p.Data.FileSize, _ = strconv.Atoi(tmp.Data.FileSize)
	p.Data.FileName = tmp.Data.FileName
	p.Data.FileData = []byte(tmp.Data.FileData)
	p.Data.DownloadTime = tmp.Data.DownloadTime

	p.ClientAddress = tmp.ClientAddress
	p.ServerAddress = tmp.ServerAddress

	p.Mode = tmp.Mode
	p.ModeRequestConfirmed, _ = strconv.ParseBool(tmp.ModeRequestConfirmed)
	p.ModeResponseConfirmed, _ = strconv.ParseBool(tmp.ModeResponseConfirmed)
	p.TransPort, _ = strconv.Atoi(tmp.TransPort)

	p.FileRequestConfirmed, _ = strconv.ParseBool(tmp.FileRequestConfirmed)
	p.FileResponseConfirmed, _ = strconv.ParseBool(tmp.FileResponseConfirmed)
	fileRequestAck, _ := strconv.ParseUint(tmp.FileRequestAck, 10, 32)
	p.FileRequestAck = uint32(fileRequestAck)

	p.DataClientPort, _ = strconv.Atoi(tmp.DataClientPort)
	p.DataServerPort, _ = strconv.Atoi(tmp.DataServerPort)
	firstSynSeq, _ := strconv.ParseUint(tmp.FirstSynSeq, 10, 32)
	p.FirstSynSeq = uint32(firstSynSeq)
	secondSynAckSeq, _ := strconv.ParseUint(tmp.SecondSynAckSeq, 10, 32)
	p.SecondSynAckSeq = uint32(secondSynAckSeq)
	p.FirstHandshaked, _ = strconv.ParseBool(tmp.FirstHandshaked)
	p.SecondHandshaked, _ = strconv.ParseBool(tmp.SecondHandshaked)
	p.ThirdHandshaked, _ = strconv.ParseBool(tmp.ThirdHandshaked)

	p.CtrlClientPort, _ = strconv.Atoi(tmp.CtrlClientPort)
	p.CtrlServerPort, _ = strconv.Atoi(tmp.CtrlServerPort)
	requestAck, _ := strconv.ParseUint(tmp.RequestAck, 10, 32)
	p.RequestAck = uint32(requestAck)

	p.LastTime, _ = strconv.ParseInt(tmp.LastTime, 10, 64)
	p.FtpDataConfirmed, _ = strconv.ParseBool(tmp.FtpDataConfirmed)
	p.FtpDataSize, _ = strconv.Atoi(tmp.FtpDataSize)
	ftpRespNum, _ := strconv.ParseUint(tmp.FtpRespNum, 10, 32)
	p.FtpRespNum = uint32(ftpRespNum)

	return p, nil
}

func GenMd5(param string) string {
	hash := md5.New()
	hash.Write([]byte(param))
	return hex.EncodeToString(hash.Sum(nil))
}

// PacketInfo 数据包报文信息
type PacketInfo struct {
	Seq       uint32 //序号
	Ack       uint32 //确认好
	SrcIp     string //源地址
	DstIp     string //目的地址
	SrcPort   int    //源端口
	DstPort   int    //目的端口
	Protocol  string //协议
	WsColInfo string //_ws.col.info from wireshark
	TcpLen    int    //tcp payload size
	Payload   []byte //tcp payload
}

// FtpSession 下载文件的ftp会话信息
type FtpSession struct {
	FileSize     int    //文件大小
	DownloadTime string //文件下载时间
	FileName     string //文件名称

	ClientAddress string //客户端-》会话源地址：下载固件的设备IP地址
	ServerAddress string //服务端-》会话目的地址：提供固件服务的服务器地址

	/**报文顺序：
	  ModeRequestConfirmed->ModeResponseConfirmed->FileRequestConfirmed->FirstHandshaked->
	    SecondHandshaked->ThirdHandshaked->FileResponseConfirmed->ftp-data
	**/

	//工作模式：主动模式、被动模式
	Mode                  string //工作模式  ACTIVE：主动模式  PASV：被动模式
	ModeRequestConfirmed  bool   //确认工作模式和数据通道端口报文，client发送PORT(主动)或者PASV(被动)命令到server
	ModeResponseConfirmed bool   //响应报文 200 or 227
	ModeRequestAck        uint32
	ModeResponseAck       uint32
	TransPort             int //PORT命令或者PASV命令协定的端口，用来数据传输

	FileRequestConfirmed  bool //client发送RETR命令报文，下载指定文件
	FileResponseConfirmed bool //server响应RETR命令报文 150
	FileRequestAck        uint32

	//数据连接通道  三次握手信息
	DataClientPort   int    //数据通道：客户端端口
	DataServerPort   int    //数据通道：服务端端口
	FirstSynSeq      uint32 //first syn sequence value
	SecondSynAckSeq  uint32 //second syn+ack sequence value
	FirstHandshaked  bool
	SecondHandshaked bool
	ThirdHandshaked  bool

	//控制通道
	CtrlClientPort int    //控制通道：客户端端口
	CtrlServerPort int    //控制通道：服务端端口
	RequestAck     uint32 //unused

	LastTime int64 //最近一次报文刷新时间

	FtpDataConfirmed bool
	FtpDataSize      int    //实际解析出来的文件大小
	FtpRespNum       uint32 //文件分包数量
	ByteData         []byte //文件内容byte
}

func ExtractFtpFile(frame *FrameData, FtpSessionMap map[string]*FtpSession) (isHandled bool) {
	// 初始化 ParserRegistry
	registry := NewParserRegistry()
	// 注册 FTP 协议解析器
	registry.Register("ftp", &FTPLayer{})

	// 解析 FTP 协议层
	parsedLayer, err := registry.ParseProtocol("ftp", frame.Layers)
	if err != nil {
		slog.Warn("ExtractFtpFile:", "Error parsing FTP protocol:", err)
		return false
	}

	ftpLayer, ok := parsedLayer.(*FTPLayer)
	if !ok {
		slog.Warn("ExtractFtpFile:", "Error parsing FTP protoco:", "invalid type")
		return false
	}
	fmt.Println(ftpLayer)

	// 处理 FTP 控制通道的 Response 消息，使用更宽松的匹配
	if frame.BaseLayers.WsCol.Protocol == "FTP" {
		// 使用更宽松的匹配条件来捕获更多可能的响应
		re := regexp.MustCompile(`Response: (\d{3}) (.+)`)
		matches := re.FindStringSubmatch(frame.BaseLayers.WsCol.Info)
		if len(matches) > 0 {
			code := matches[1]
			message := matches[2]
			slog.Warn("ExtractFtpFile:", "FTP Response Code:", code, "Message:", message)

			// 判断是否为文件传输的响应
			if code == "150" {
				return handleFtpResponse150(frame, FtpSessionMap)
			}
		}
	}

	// 处理 FTP-DATA 协议层
	if frame.BaseLayers.WsCol.Protocol == "FTP-DATA" {
		return handleFtpData(frame, FtpSessionMap)
	}

	return false
}

// handleFtpResponse150 处理 FTP 控制通道的 Response: 150 消息
func handleFtpResponse150(frame *FrameData, FtpSessionMap map[string]*FtpSession) bool {
	// 使用正则提取文件名和文件大小
	fileNameRegex := regexp.MustCompile(`Opening (.+?) \(`) // 改为更宽松的匹配
	fileSizeRegex := regexp.MustCompile(`\((\d+) bytes\)`)  // 提取文件大小

	// 解析文件名
	fileNameMatches := fileNameRegex.FindStringSubmatch(frame.BaseLayers.WsCol.Info)
	fileSizeMatches := fileSizeRegex.FindStringSubmatch(frame.BaseLayers.WsCol.Info)

	if len(fileNameMatches) < 2 || len(fileSizeMatches) < 2 {
		slog.Warn("ExtractFtpFile:", "Failed to extract filename or filesize from FTP Response 150.", "")
		return false
	}

	fileName := fileNameMatches[1]
	fileSize, _ := strconv.Atoi(fileSizeMatches[1])

	// 生成会话的唯一键
	param := frame.BaseLayers.Ip.Src + frame.BaseLayers.Ip.Dst + fileName
	key := GenMd5(param)

	// 检查是否已存在会话
	if tmpSession := FtpSessionMap[key]; tmpSession == nil {
		// 创建新的 FTP 会话
		FtpSessionMap[key] = &FtpSession{
			FileSize:      fileSize,
			FileName:      fileName,
			ClientAddress: frame.BaseLayers.Ip.Src,
			ServerAddress: frame.BaseLayers.Ip.Dst,
			LastTime:      time.Now().Unix(),
		}
	} else {
		// 重复的 Response: 150 消息
		fmt.Printf("%s to %s transfer ftp fileName:%s Response: 150 packet is duplicated.\n",
			frame.BaseLayers.Ip.Src, frame.BaseLayers.Ip.Dst, fileName)
	}

	return true
}

// handleFtpData 处理 FTP-DATA 协议层
func handleFtpData(frame *FrameData, FtpSessionMap map[string]*FtpSession) bool {
	// 检查数据传输模式和命令
	method, methodOk := frame.Layers["ftp-data.setup-method"].(string)
	command, commandOk := frame.Layers["ftp-data.command"].(string)

	if !methodOk || !commandOk || (method != "PORT" && method != "PASV") || !strings.HasPrefix(command, "RETR ") {
		fmt.Println("Invalid FTP-DATA packet:")
		fmt.Println("ftp-data.command is", command)
		fmt.Println("ftp-data.setup-method is", method)
		return true
	}

	// 提取文件名
	filename := strings.Split(command, " ")[1]

	// 查找对应的 FTP 会话
	szParam := frame.BaseLayers.Ip.Src + frame.BaseLayers.Ip.Dst + filename
	szKey := GenMd5(szParam)
	szSession := FtpSessionMap[szKey]

	if szSession == nil {
		// 未找到对应的 FTP 会话
		fmt.Println("has not find sz_session.")
		return true
	}

	// 生成数据通道的唯一键
	dataParam := frame.BaseLayers.Ip.Src + frame.BaseLayers.Ip.Dst +
		strconv.Itoa(frame.BaseLayers.Tcp.SrcPort) + strconv.Itoa(frame.BaseLayers.Tcp.DstPort) + method + filename
	dataKey := GenMd5(dataParam)

	var payload []byte
	if frame.BaseLayers.Tcp.Payload != "" {
		data := strings.ReplaceAll(frame.BaseLayers.Tcp.Payload, ":", "")
		var decodeErr error
		payload, decodeErr = hex.DecodeString(data)
		if decodeErr != nil {
			fmt.Println("decode hex error:", decodeErr.Error())
			return true
		}
	}

	// 检查是否已存在数据通道会话
	if tmpSession := FtpSessionMap[dataKey]; tmpSession == nil {
		// 创建新的数据通道会话
		FtpSessionMap[dataKey] = &FtpSession{
			FileSize:       szSession.FileSize,
			Mode:           method,
			FileName:       filename,
			ClientAddress:  frame.BaseLayers.Ip.Src,
			ServerAddress:  frame.BaseLayers.Ip.Dst,
			CtrlClientPort: frame.BaseLayers.Tcp.SrcPort,
			CtrlServerPort: frame.BaseLayers.Tcp.DstPort,
			LastTime:       time.Now().Unix(),
			ByteData:       payload,
			FtpDataSize:    frame.BaseLayers.Tcp.Len,
			FtpRespNum:     1,
		}
	} else {
		// 追加数据
		tmpSession.ByteData = append(tmpSession.ByteData, payload...)
		tmpSession.FtpDataSize += frame.BaseLayers.Tcp.Len
		tmpSession.FtpRespNum++

		// 检查文件是否完整
		if tmpSession.FtpDataSize >= tmpSession.FileSize {
			// 文件传输完成，保存文件
			CreateFileFtp(tmpSession)
			delete(FtpSessionMap, szKey)
			delete(FtpSessionMap, dataKey)
		}
	}

	return true
}

// CreateFileFtp 生成FTP提取的文件
func CreateFileFtp(tmpSession *FtpSession) error {
	fPath := GenerateUniqueFilenameWithIncrement(tmpSession.FileName)

	file, err := os.Create(fPath)
	if err != nil {
		return fmt.Errorf("error creating FTP file: %v", err)
	}
	defer file.Close()

	_, err = file.Write(tmpSession.ByteData)
	if err != nil {
		return fmt.Errorf("error writing FTP file: %v", err)
	}

	fmt.Println("FTP create transfer file:", tmpSession.FileName)

	// 如果文件大小匹配，标记为文件完整
	isIntact := false
	if tmpSession.FileSize == tmpSession.FtpDataSize {
		isIntact = true
	}

	fmt.Println("isIntact:", isIntact)

	return nil
}
