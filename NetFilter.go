package main

import (
	"fmt"
	"syscall"
	"unsafe"
)

const (
	// 定义常量
	NF_STATUS_SUCCESS              = 0
	NF_STATUS_FAIL                 = -1
	NF_STATUS_INVALID_ENDPOINT_ID  = -2
	NF_STATUS_NOT_INITIALIZED      = -3
	NF_STATUS_IO_ERROR             = -4
	NF_STATUS_REBOOT_REQUIRED      = -5
	NF_D_IN                        = 1
	NF_D_OUT                       = 2
	NF_D_BOTH                      = 3
	NF_ALLOW                       = 0
	NF_BLOCK                       = 1
	NF_FILTER                      = 2
	NF_SUSPENDED                   = 4
	NF_OFFLINE                     = 8
	NF_INDICATE_CONNECT_REQUESTS   = 16
	NF_DISABLE_REDIRECT_PROTECTION = 32
	NF_PEND_CONNECT_REQUEST        = 64
	NF_FILTER_AS_IP_PACKETS        = 128
	NF_READONLY                    = 256
	NF_CONTROL_FLOW                = 512
	NF_REDIRECT                    = 1024
	NF_BYPASS_IP_PACKETS           = 2048
	IPPROTO_TCP                    = 6
	IPPROTO_UDP                    = 17
	AF_INET                        = 2
	AF_INET6                       = 23
	NF_TCP_PACKET_BUF_SIZE         = 8192
	NF_UDP_PACKET_BUF_SIZE         = 131072 // 2 * 65536
	NF_MAX_ADDRESS_LENGTH          = 28
	NF_MAX_IP_ADDRESS_LENGTH       = 16
	MAX_PATH                       = 260
)

type (
	// 定义结构体
	NF_STATUS         int32
	NF_DIRECTION      byte
	NF_FILTERING_FLAG uint32
	ENDPOINT_ID       uint64
	NF_DATA_CODE      uint32

	NF_IP_FLAG uint32

	NF_RULE struct {
		Protocol            int32
		ProcessId           uint32
		Direction           NF_DIRECTION
		LocalPort           uint16
		RemotePort          uint16
		IpFamily            uint16
		LocalIpAddress      [NF_MAX_IP_ADDRESS_LENGTH]byte
		LocalIpAddressMask  [NF_MAX_IP_ADDRESS_LENGTH]byte
		RemoteIpAddress     [NF_MAX_IP_ADDRESS_LENGTH]byte
		RemoteIpAddressMask [NF_MAX_IP_ADDRESS_LENGTH]byte
		FilteringFlag       NF_FILTERING_FLAG
	}

	NF_PORT_RANGE struct {
		ValueLow  uint16
		ValueHigh uint16
	}

	NF_RULE_EX struct {
		Protocol            int32
		ProcessId           uint32
		Direction           NF_DIRECTION
		LocalPort           uint16
		RemotePort          uint16
		IpFamily            uint16
		LocalIpAddress      [NF_MAX_IP_ADDRESS_LENGTH]byte
		LocalIpAddressMask  [NF_MAX_IP_ADDRESS_LENGTH]byte
		RemoteIpAddress     [NF_MAX_IP_ADDRESS_LENGTH]byte
		RemoteIpAddressMask [NF_MAX_IP_ADDRESS_LENGTH]byte
		FilteringFlag       NF_FILTERING_FLAG
		ProcessName         [MAX_PATH]uint16
		LocalPortRange      NF_PORT_RANGE
		RemotePortRange     NF_PORT_RANGE
		RedirectTo          [NF_MAX_ADDRESS_LENGTH]byte
		LocalProxyProcessId uint32
	}

	NF_TCP_CONN_INFO struct {
		FilteringFlag NF_FILTERING_FLAG
		ProcessId     uint32
		Direction     NF_DIRECTION
		IpFamily      uint16
		LocalAddress  [NF_MAX_ADDRESS_LENGTH]byte
		RemoteAddress [NF_MAX_ADDRESS_LENGTH]byte
	}

	NF_UDP_CONN_INFO struct {
		ProcessId    uint32
		IpFamily     uint16
		LocalAddress [NF_MAX_ADDRESS_LENGTH]byte
	}

	NF_UDP_CONN_REQUEST struct {
		FilteringFlag NF_FILTERING_FLAG
		ProcessId     uint32
		IpFamily      uint16
		LocalAddress  [NF_MAX_ADDRESS_LENGTH]byte
		RemoteAddress [NF_MAX_ADDRESS_LENGTH]byte
	}

	NF_UDP_OPTIONS struct {
		Flags         NF_IP_FLAG
		OptionsLength int32
		Options       [1]byte
	}

	NF_IP_PACKET_OPTIONS struct {
		IpFamily          uint16
		IpHeaderSize      uint32
		CompartmentId     uint32
		InterfaceIndex    uint32
		SubInterfaceIndex uint32
		Flags             NF_IP_FLAG
	}

	NF_FLOWCTL_DATA struct {
		InLimit  uint64
		OutLimit uint64
	}

	NF_FLOWCTL_MODIFY_DATA struct {
		FcHandle uint32
		Data     NF_FLOWCTL_DATA
	}

	NF_FLOWCTL_STAT struct {
		InBytes  uint64
		OutBytes uint64
	}

	NF_FLOWCTL_SET_DATA struct {
		EndpointId uint64
		FcHandle   uint32
	}

	NF_BINDING_RULE struct {
		Protocol           int32
		ProcessId          uint32
		ProcessName        [MAX_PATH]uint16
		LocalPort          uint16
		IpFamily           uint16
		LocalIpAddress     [NF_MAX_IP_ADDRESS_LENGTH]byte
		LocalIpAddressMask [NF_MAX_IP_ADDRESS_LENGTH]byte
		NewLocalIpAddress  [NF_MAX_ADDRESS_LENGTH]byte
		NewLocalPort       uint16
		FilteringFlag      NF_FILTERING_FLAG
	}

	NF_EventHandler struct {
		threadStart       uintptr
		threadEnd         uintptr
		tcpConnectRequest uintptr
		tcpConnected      uintptr
		tcpClosed         uintptr
		tcpReceive        uintptr
		tcpSend           uintptr
		tcpCanReceive     uintptr
		tcpCanSend        uintptr
		udpCreated        uintptr
		udpConnectRequest uintptr
		udpClosed         uintptr
		udpReceive        uintptr
		udpSend           uintptr
		udpCanReceive     uintptr
		udpCanSend        uintptr
	}

	NF_IPEventHandler struct {
		ipReceive uintptr
		ipSend    uintptr
	}
)

// 加载DLL
var (
	modNetFilterSDK = syscall.NewLazyDLL("NetFilterSDK.dll")

	procNfInit                      = modNetFilterSDK.NewProc("nf_init")
	procNfFree                      = modNetFilterSDK.NewProc("nf_free")
	procNfRegisterDriver            = modNetFilterSDK.NewProc("nf_registerDriver")
	procNfRegisterDriverEx          = modNetFilterSDK.NewProc("nf_registerDriverEx")
	procNfUnRegisterDriver          = modNetFilterSDK.NewProc("nf_unRegisterDriver")
	procNfTcpSetConnectionState     = modNetFilterSDK.NewProc("nf_tcpSetConnectionState")
	procNfTcpPostSend               = modNetFilterSDK.NewProc("nf_tcpPostSend")
	procNfTcpPostReceive            = modNetFilterSDK.NewProc("nf_tcpPostReceive")
	procNfTcpClose                  = modNetFilterSDK.NewProc("nf_tcpClose")
	procNfSetTCPTimeout             = modNetFilterSDK.NewProc("nf_setTCPTimeout")
	procNfTcpDisableFiltering       = modNetFilterSDK.NewProc("nf_tcpDisableFiltering")
	procNfUdpSetConnectionState     = modNetFilterSDK.NewProc("nf_udpSetConnectionState")
	procNfUdpPostSend               = modNetFilterSDK.NewProc("nf_udpPostSend")
	procNfUdpPostReceive            = modNetFilterSDK.NewProc("nf_udpPostReceive")
	procNfUdpDisableFiltering       = modNetFilterSDK.NewProc("nf_udpDisableFiltering")
	procNfIpPostSend                = modNetFilterSDK.NewProc("nf_ipPostSend")
	procNfIpPostReceive             = modNetFilterSDK.NewProc("nf_ipPostReceive")
	procNfAddRule                   = modNetFilterSDK.NewProc("nf_addRule")
	procNfDeleteRules               = modNetFilterSDK.NewProc("nf_deleteRules")
	procNfSetRules                  = modNetFilterSDK.NewProc("nf_setRules")
	procNfAddRuleEx                 = modNetFilterSDK.NewProc("nf_addRuleEx")
	procNfSetRulesEx                = modNetFilterSDK.NewProc("nf_setRulesEx")
	procNfGetConnCount              = modNetFilterSDK.NewProc("nf_getConnCount")
	procNfTcpSetSockOpt             = modNetFilterSDK.NewProc("nf_tcpSetSockOpt")
	procNfGetProcessNameA           = modNetFilterSDK.NewProc("nf_getProcessNameA")
	procNfGetProcessNameW           = modNetFilterSDK.NewProc("nf_getProcessNameW")
	procNfGetProcessNameFromKernel  = modNetFilterSDK.NewProc("nf_getProcessNameFromKernel")
	procNfAdjustProcessPriviledges  = modNetFilterSDK.NewProc("nf_adjustProcessPriviledges")
	procNfTcpIsProxy                = modNetFilterSDK.NewProc("nf_tcpIsProxy")
	procNfSetOptions                = modNetFilterSDK.NewProc("nf_setOptions")
	procNfCompleteTCPConnectRequest = modNetFilterSDK.NewProc("nf_completeTCPConnectRequest")
	procNfCompleteUDPConnectRequest = modNetFilterSDK.NewProc("nf_completeUDPConnectRequest")
	procNfGetTCPConnInfo            = modNetFilterSDK.NewProc("nf_getTCPConnInfo")
	procNfGetUDPConnInfo            = modNetFilterSDK.NewProc("nf_getUDPConnInfo")
	procNfSetIPEventHandler         = modNetFilterSDK.NewProc("nf_setIPEventHandler")
	procNfAddFlowCtl                = modNetFilterSDK.NewProc("nf_addFlowCtl")
	procNfDeleteFlowCtl             = modNetFilterSDK.NewProc("nf_deleteFlowCtl")
	procNfSetTCPFlowCtl             = modNetFilterSDK.NewProc("nf_setTCPFlowCtl")
	procNfSetUDPFlowCtl             = modNetFilterSDK.NewProc("nf_setUDPFlowCtl")
	procNfModifyFlowCtl             = modNetFilterSDK.NewProc("nf_modifyFlowCtl")
	procNfGetFlowCtlStat            = modNetFilterSDK.NewProc("nf_getFlowCtlStat")
	procNfGetTCPStat                = modNetFilterSDK.NewProc("nf_getTCPStat")
	procNfGetUDPStat                = modNetFilterSDK.NewProc("nf_getUDPStat")
	procNfAddBindingRule            = modNetFilterSDK.NewProc("nf_addBindingRule")
	procNfDeleteBindingRules        = modNetFilterSDK.NewProc("nf_deleteBindingRules")
	procNfGetDriverType             = modNetFilterSDK.NewProc("nf_getDriverType")
)

// 定义回调函数
var (
	nfThreadStartCallback       = syscall.NewCallback(nfThreadStart)
	nfThreadEndCallback         = syscall.NewCallback(nfThreadEnd)
	nfTcpConnectRequestCallback = syscall.NewCallback(nfTcpConnectRequest)
	nfTcpConnectedCallback      = syscall.NewCallback(nfTcpConnected)
	nfTcpClosedCallback         = syscall.NewCallback(nfTcpClosed)
	nfTcpReceiveCallback        = syscall.NewCallback(nfTcpReceive)
	nfTcpSendCallback           = syscall.NewCallback(nfTcpSend)
	nfTcpCanReceiveCallback     = syscall.NewCallback(nfTcpCanReceive)
	nfTcpCanSendCallback        = syscall.NewCallback(nfTcpCanSend)
	nfUdpCreatedCallback        = syscall.NewCallback(nfUdpCreated)
	nfUdpConnectRequestCallback = syscall.NewCallback(nfUdpConnectRequest)
	nfUdpClosedCallback         = syscall.NewCallback(nfUdpClosed)
	nfUdpReceiveCallback        = syscall.NewCallback(nfUdpReceive)
	nfUdpSendCallback           = syscall.NewCallback(nfUdpSend)
	nfUdpCanReceiveCallback     = syscall.NewCallback(nfUdpCanReceive)
	nfUdpCanSendCallback        = syscall.NewCallback(nfUdpCanSend)
	nfIpReceiveCallback         = syscall.NewCallback(nfIpReceive)
	nfIpSendCallback            = syscall.NewCallback(nfIpSend)
)

// 回调函数实现
func nfThreadStart() {
	fmt.Println("Thread Started")
}

func nfThreadEnd() {
	fmt.Println("Thread Ended")
}

func nfTcpConnectRequest(id ENDPOINT_ID, connInfo *NF_TCP_CONN_INFO) {
	fmt.Printf("TCP Connect Request: ID=%d\n", id)
}

func nfTcpConnected(id ENDPOINT_ID, connInfo *NF_TCP_CONN_INFO) {
	fmt.Printf("TCP Connected: ID=%d\n", id)
}

func nfTcpClosed(id ENDPOINT_ID, connInfo *NF_TCP_CONN_INFO) {
	fmt.Printf("TCP Closed: ID=%d\n", id)
}

func nfTcpReceive(id ENDPOINT_ID, buf *byte, len int32) {
	fmt.Printf("TCP Receive: ID=%d, Len=%d\n", id, len)
}

func nfTcpSend(id ENDPOINT_ID, buf *byte, len int32) {
	fmt.Printf("TCP Send: ID=%d, Len=%d\n", id, len)
}

func nfTcpCanReceive(id ENDPOINT_ID) {
	fmt.Printf("TCP Can Receive: ID=%d\n", id)
}

func nfTcpCanSend(id ENDPOINT_ID) {
	fmt.Printf("TCP Can Send: ID=%d\n", id)
}

func nfUdpCreated(id ENDPOINT_ID, connInfo *NF_UDP_CONN_INFO) {
	fmt.Printf("UDP Created: ID=%d\n", id)
}

func nfUdpConnectRequest(id ENDPOINT_ID, connInfo *NF_UDP_CONN_REQUEST) {
	fmt.Printf("UDP Connect Request: ID=%d\n", id)
}

func nfUdpClosed(id ENDPOINT_ID, connInfo *NF_UDP_CONN_INFO) {
	fmt.Printf("UDP Closed: ID=%d\n", id)
}

func nfUdpReceive(id ENDPOINT_ID, remoteAddress *byte, buf *byte, len int32, options *NF_UDP_OPTIONS) {
	fmt.Printf("UDP Receive: ID=%d, Len=%d\n", id, len)
}

func nfUdpSend(id ENDPOINT_ID, remoteAddress *byte, buf *byte, len int32, options *NF_UDP_OPTIONS) {
	fmt.Printf("UDP Send: ID=%d, Len=%d\n", id, len)
}

func nfUdpCanReceive(id ENDPOINT_ID) {
	fmt.Printf("UDP Can Receive: ID=%d\n", id)
}

func nfUdpCanSend(id ENDPOINT_ID) {
	fmt.Printf("UDP Can Send: ID=%d\n", id)
}

func nfIpReceive(buf *byte, len int32, options *NF_IP_PACKET_OPTIONS) {
	fmt.Printf("IP Receive: Len=%d\n", len)
}

func nfIpSend(buf *byte, len int32, options *NF_IP_PACKET_OPTIONS) {
	fmt.Printf("IP Send: Len=%d\n", len)
}

// 绑定SDK的API
func nfInitGo(driverName string, handler *NF_EventHandler) NF_STATUS {
	ret, _, _ := procNfInit.Call(
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(driverName))),
		handler.threadStart,
		handler.threadEnd,
		handler.tcpConnectRequest,
		handler.tcpConnected,
		handler.tcpClosed,
		handler.tcpReceive,
		handler.tcpSend,
		handler.tcpCanReceive,
		handler.tcpCanSend,
		handler.udpCreated,
		handler.udpConnectRequest,
		handler.udpClosed,
		handler.udpReceive,
		handler.udpSend,
		handler.udpCanReceive,
		handler.udpCanSend,
	)
	return NF_STATUS(ret)
}

func nfFreeGo() {
	procNfFree.Call()
}

func nfRegisterDriverGo(driverName string) NF_STATUS {
	ret, _, _ := procNfRegisterDriver.Call(uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(driverName))))
	return NF_STATUS(ret)
}

func nfRegisterDriverExGo(driverName string, driverPath string) NF_STATUS {
	ret, _, _ := procNfRegisterDriverEx.Call(
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(driverName))),
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(driverPath))),
	)
	return NF_STATUS(ret)
}

func nfUnRegisterDriverGo(driverName string) NF_STATUS {
	ret, _, _ := procNfUnRegisterDriver.Call(uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(driverName))))
	return NF_STATUS(ret)
}

func nfTcpSetConnectionStateGo(id ENDPOINT_ID, suspended int32) NF_STATUS {
	ret, _, _ := procNfTcpSetConnectionState.Call(uintptr(id), uintptr(suspended))
	return NF_STATUS(ret)
}

func nfTcpPostSendGo(id ENDPOINT_ID, buf *byte, len int32) NF_STATUS {
	ret, _, _ := procNfTcpPostSend.Call(uintptr(id), uintptr(unsafe.Pointer(buf)), uintptr(len))
	return NF_STATUS(ret)
}

func nfTcpPostReceiveGo(id ENDPOINT_ID, buf *byte, len int32) NF_STATUS {
	ret, _, _ := procNfTcpPostReceive.Call(uintptr(id), uintptr(unsafe.Pointer(buf)), uintptr(len))
	return NF_STATUS(ret)
}

func nfTcpCloseGo(id ENDPOINT_ID) NF_STATUS {
	ret, _, _ := procNfTcpClose.Call(uintptr(id))
	return NF_STATUS(ret)
}

func nfSetTCPTimeoutGo(timeout uint32) uint32 {
	ret, _, _ := procNfSetTCPTimeout.Call(uintptr(timeout))
	return uint32(ret)
}

func nfTcpDisableFilteringGo(id ENDPOINT_ID) NF_STATUS {
	ret, _, _ := procNfTcpDisableFiltering.Call(uintptr(id))
	return NF_STATUS(ret)
}

func nfUdpSetConnectionStateGo(id ENDPOINT_ID, suspended int32) NF_STATUS {
	ret, _, _ := procNfUdpSetConnectionState.Call(uintptr(id), uintptr(suspended))
	return NF_STATUS(ret)
}

func nfUdpPostSendGo(id ENDPOINT_ID, remoteAddress *byte, buf *byte, len int32, options *NF_UDP_OPTIONS) NF_STATUS {
	ret, _, _ := procNfUdpPostSend.Call(
		uintptr(id),
		uintptr(unsafe.Pointer(remoteAddress)),
		uintptr(unsafe.Pointer(buf)),
		uintptr(len),
		uintptr(unsafe.Pointer(options)),
	)
	return NF_STATUS(ret)
}

func nfUdpPostReceiveGo(id ENDPOINT_ID, remoteAddress *byte, buf *byte, len int32, options *NF_UDP_OPTIONS) NF_STATUS {
	ret, _, _ := procNfUdpPostReceive.Call(
		uintptr(id),
		uintptr(unsafe.Pointer(remoteAddress)),
		uintptr(unsafe.Pointer(buf)),
		uintptr(len),
		uintptr(unsafe.Pointer(options)),
	)
	return NF_STATUS(ret)
}

func nfUdpDisableFilteringGo(id ENDPOINT_ID) NF_STATUS {
	ret, _, _ := procNfUdpDisableFiltering.Call(uintptr(id))
	return NF_STATUS(ret)
}

func nfIpPostSendGo(buf *byte, len int32, options *NF_IP_PACKET_OPTIONS) NF_STATUS {
	ret, _, _ := procNfIpPostSend.Call(
		uintptr(unsafe.Pointer(buf)),
		uintptr(len),
		uintptr(unsafe.Pointer(options)),
	)
	return NF_STATUS(ret)
}

func nfIpPostReceiveGo(buf *byte, len int32, options *NF_IP_PACKET_OPTIONS) NF_STATUS {
	ret, _, _ := procNfIpPostReceive.Call(
		uintptr(unsafe.Pointer(buf)),
		uintptr(len),
		uintptr(unsafe.Pointer(options)),
	)
	return NF_STATUS(ret)
}

func nfAddRuleGo(rule *NF_RULE, toHead int32) NF_STATUS {
	ret, _, _ := procNfAddRule.Call(uintptr(unsafe.Pointer(rule)), uintptr(toHead))
	return NF_STATUS(ret)
}

func nfDeleteRulesGo() NF_STATUS {
	ret, _, _ := procNfDeleteRules.Call()
	return NF_STATUS(ret)
}

func nfSetRulesGo(rules []NF_RULE, count int32) NF_STATUS {
	ret, _, _ := procNfSetRules.Call(uintptr(unsafe.Pointer(&rules[0])), uintptr(count))
	return NF_STATUS(ret)
}

func nfAddRuleExGo(rule *NF_RULE_EX, toHead int32) NF_STATUS {
	ret, _, _ := procNfAddRuleEx.Call(uintptr(unsafe.Pointer(rule)), uintptr(toHead))
	return NF_STATUS(ret)
}

func nfSetRulesExGo(rules []NF_RULE_EX, count int32) NF_STATUS {
	ret, _, _ := procNfSetRulesEx.Call(uintptr(unsafe.Pointer(&rules[0])), uintptr(count))
	return NF_STATUS(ret)
}

func nfGetConnCountGo() uint32 {
	ret, _, _ := procNfGetConnCount.Call()
	return uint32(ret)
}

func nfTcpSetSockOptGo(id ENDPOINT_ID, optname int32, optval *byte, optlen int32) NF_STATUS {
	ret, _, _ := procNfTcpSetSockOpt.Call(uintptr(id), uintptr(optname), uintptr(unsafe.Pointer(optval)), uintptr(optlen))
	return NF_STATUS(ret)
}

func nfGetProcessNameAGo(processId uint32, buf *byte, len uint32) bool {
	ret, _, _ := procNfGetProcessNameA.Call(uintptr(processId), uintptr(unsafe.Pointer(buf)), uintptr(len))
	return ret != 0
}

func nfGetProcessNameWGo(processId uint32, buf *uint16, len uint32) bool {
	ret, _, _ := procNfGetProcessNameW.Call(uintptr(processId), uintptr(unsafe.Pointer(buf)), uintptr(len))
	return ret != 0
}

func nfGetProcessNameFromKernelGo(processId uint32, buf *uint16, len uint32) bool {
	ret, _, _ := procNfGetProcessNameFromKernel.Call(uintptr(processId), uintptr(unsafe.Pointer(buf)), uintptr(len))
	return ret != 0
}

func nfAdjustProcessPriviledgesGo() {
	procNfAdjustProcessPriviledges.Call()
}

func nfTcpIsProxyGo(processId uint32) bool {
	ret, _, _ := procNfTcpIsProxy.Call(uintptr(processId))
	return ret != 0
}

func nfSetOptionsGo(nThreads uint32, flags uint32) {
	procNfSetOptions.Call(uintptr(nThreads), uintptr(flags))
}

func nfCompleteTCPConnectRequestGo(id ENDPOINT_ID, connInfo *NF_TCP_CONN_INFO) NF_STATUS {
	ret, _, _ := procNfCompleteTCPConnectRequest.Call(uintptr(id), uintptr(unsafe.Pointer(connInfo)))
	return NF_STATUS(ret)
}

func nfCompleteUDPConnectRequestGo(id ENDPOINT_ID, connInfo *NF_UDP_CONN_REQUEST) NF_STATUS {
	ret, _, _ := procNfCompleteUDPConnectRequest.Call(uintptr(id), uintptr(unsafe.Pointer(connInfo)))
	return NF_STATUS(ret)
}

func nfGetTCPConnInfoGo(id ENDPOINT_ID, connInfo *NF_TCP_CONN_INFO) NF_STATUS {
	ret, _, _ := procNfGetTCPConnInfo.Call(uintptr(id), uintptr(unsafe.Pointer(connInfo)))
	return NF_STATUS(ret)
}

func nfGetUDPConnInfoGo(id ENDPOINT_ID, connInfo *NF_UDP_CONN_INFO) NF_STATUS {
	ret, _, _ := procNfGetUDPConnInfo.Call(uintptr(id), uintptr(unsafe.Pointer(connInfo)))
	return NF_STATUS(ret)
}

func nfSetIPEventHandlerGo(handler *NF_IPEventHandler) {
	procNfSetIPEventHandler.Call(handler.ipReceive, handler.ipSend)
}

func nfAddFlowCtlGo(data *NF_FLOWCTL_DATA, fcHandle *uint32) NF_STATUS {
	ret, _, _ := procNfAddFlowCtl.Call(uintptr(unsafe.Pointer(data)), uintptr(unsafe.Pointer(fcHandle)))
	return NF_STATUS(ret)
}

func nfDeleteFlowCtlGo(fcHandle uint32) NF_STATUS {
	ret, _, _ := procNfDeleteFlowCtl.Call(uintptr(fcHandle))
	return NF_STATUS(ret)
}

func nfSetTCPFlowCtlGo(id ENDPOINT_ID, fcHandle uint32) NF_STATUS {
	ret, _, _ := procNfSetTCPFlowCtl.Call(uintptr(id), uintptr(fcHandle))
	return NF_STATUS(ret)
}

func nfSetUDPFlowCtlGo(id ENDPOINT_ID, fcHandle uint32) NF_STATUS {
	ret, _, _ := procNfSetUDPFlowCtl.Call(uintptr(id), uintptr(fcHandle))
	return NF_STATUS(ret)
}

func nfModifyFlowCtlGo(fcHandle uint32, data *NF_FLOWCTL_DATA) NF_STATUS {
	ret, _, _ := procNfModifyFlowCtl.Call(uintptr(fcHandle), uintptr(unsafe.Pointer(data)))
	return NF_STATUS(ret)
}

func nfGetFlowCtlStatGo(fcHandle uint32, stat *NF_FLOWCTL_STAT) NF_STATUS {
	ret, _, _ := procNfGetFlowCtlStat.Call(uintptr(fcHandle), uintptr(unsafe.Pointer(stat)))
	return NF_STATUS(ret)
}

func nfGetTCPStatGo(id ENDPOINT_ID, stat *NF_FLOWCTL_STAT) NF_STATUS {
	ret, _, _ := procNfGetTCPStat.Call(uintptr(id), uintptr(unsafe.Pointer(stat)))
	return NF_STATUS(ret)
}

func nfGetUDPStatGo(id ENDPOINT_ID, stat *NF_FLOWCTL_STAT) NF_STATUS {
	ret, _, _ := procNfGetUDPStat.Call(uintptr(id), uintptr(unsafe.Pointer(stat)))
	return NF_STATUS(ret)
}

func nfAddBindingRuleGo(rule *NF_BINDING_RULE, toHead int32) NF_STATUS {
	ret, _, _ := procNfAddBindingRule.Call(uintptr(unsafe.Pointer(rule)), uintptr(toHead))
	return NF_STATUS(ret)
}

func nfDeleteBindingRulesGo() NF_STATUS {
	ret, _, _ := procNfDeleteBindingRules.Call()
	return NF_STATUS(ret)
}

func nfGetDriverTypeGo() uint32 {
	ret, _, _ := procNfGetDriverType.Call()
	return uint32(ret)
}

func main() {
	handler := &NF_EventHandler{
		threadStart:       nfThreadStartCallback,
		threadEnd:         nfThreadEndCallback,
		tcpConnectRequest: nfTcpConnectRequestCallback,
		tcpConnected:      nfTcpConnectedCallback,
		tcpClosed:         nfTcpClosedCallback,
		tcpReceive:        nfTcpReceiveCallback,
		tcpSend:           nfTcpSendCallback,
		tcpCanReceive:     nfTcpCanReceiveCallback,
		tcpCanSend:        nfTcpCanSendCallback,
		udpCreated:        nfUdpCreatedCallback,
		udpConnectRequest: nfUdpConnectRequestCallback,
		udpClosed:         nfUdpClosedCallback,
		udpReceive:        nfUdpReceiveCallback,
		udpSend:           nfUdpSendCallback,
		udpCanReceive:     nfUdpCanReceiveCallback,
		udpCanSend:        nfUdpCanSendCallback,
	}

	ipHandler := &NF_IPEventHandler{
		ipReceive: nfIpReceiveCallback,
		ipSend:    nfIpSendCallback,
	}

	status := nfInitGo("myDriver", handler)
	if status != NF_STATUS_SUCCESS {
		fmt.Printf("Failed to initialize: %d\n", status)
		return
	}
	defer nfFreeGo()

	nfSetIPEventHandlerGo(ipHandler)

	// 添加规则示例
	rule := NF_RULE{
		Protocol:      IPPROTO_TCP,
		ProcessId:     0,
		Direction:     NF_D_OUT,
		LocalPort:     0,
		RemotePort:    80,
		IpFamily:      AF_INET,
		FilteringFlag: NF_FILTER,
	}
	status = nfAddRuleGo(&rule, 1)
	if status != NF_STATUS_SUCCESS {
		fmt.Printf("Failed to add rule: %d\n", status)
		return
	}

	// 获取连接计数示例
	connCount := nfGetConnCountGo()
	fmt.Printf("Connection count: %d\n", connCount)
}
