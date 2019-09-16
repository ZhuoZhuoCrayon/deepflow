package flowgenerator

import (
	"time"

	. "gitlab.x.lan/yunshan/droplet-libs/datatype"
)

func (m *FlowMap) updateFlowStateMachine(flowExtra *FlowExtra, flags uint8, serverToClient bool) bool {
	taggedFlow := flowExtra.taggedFlow
	var timeout time.Duration
	var flowState FlowState
	closed := false
	if stateValue := m.stateMachineMaster[flowExtra.flowState][flags&TCP_FLAG_MASK]; stateValue != nil {
		timeout = stateValue.timeout
		flowState = stateValue.flowState
		closed = stateValue.closed
	} else {
		timeout = exceptionTimeout
		flowState = FLOW_STATE_EXCEPTION
		closed = false
	}
	if serverToClient { // 若flags对应的包是 服务端->客户端 时，还需要走一下Slave状态机
		if stateValue := m.stateMachineSlave[flowExtra.flowState][flags&TCP_FLAG_MASK]; stateValue != nil {
			timeout = stateValue.timeout
			flowState = stateValue.flowState
			closed = stateValue.closed
		}
	}
	flowExtra.flowState = flowState
	if taggedFlow.FlowMetricsPeers[FLOW_METRICS_PEER_SRC].TotalPacketCount == 0 ||
		taggedFlow.FlowMetricsPeers[FLOW_METRICS_PEER_DST].TotalPacketCount == 0 {
		flowExtra.timeout = singleDirectionTimeout
	} else {
		flowExtra.timeout = timeout
	}
	return closed
}

func (m *FlowMap) initTcpFlow(flowExtra *FlowExtra, meta *MetaPacket) {
	now := meta.Timestamp
	m.initFlow(flowExtra, meta, now)
	taggedFlow := flowExtra.taggedFlow
	flags := uint8(0)
	if meta.TcpData != nil {
		flags = meta.TcpData.Flags
	}
	flowMetricsPeerSrc := &taggedFlow.FlowMetricsPeers[FLOW_METRICS_PEER_SRC]
	flowMetricsPeerSrc.TCPFlags |= flags
	flowMetricsPeerSrc.ArrTime0 = now
	flowMetricsPeerSrc.ArrTimeLast = now
	flowMetricsPeerSrc.TotalPacketCount = 1
	flowMetricsPeerSrc.PacketCount = 1
	flowMetricsPeerSrc.TickPacketCount = 1
	flowMetricsPeerSrc.TotalByteCount = uint64(meta.PacketLen)
	flowMetricsPeerSrc.ByteCount = uint64(meta.PacketLen)
	flowMetricsPeerSrc.TickByteCount = uint64(meta.PacketLen)
	updatePlatformData(taggedFlow, meta.EndpointData, false)
	m.fillGeoInfo(taggedFlow)

	m.updateTCPDirection(meta, flags, flowExtra, true)
	flowExtra.setMetaPacketActiveService(meta)

	if StatePreprocess(meta, flags) || meta.Invalid {
		flowExtra.timeout = exceptionTimeout
		flowExtra.flowState = FLOW_STATE_EXCEPTION
	}

	m.updateFlowStateMachine(flowExtra, flags, meta.Direction == SERVER_TO_CLIENT)
}

func (m *FlowMap) updateTcpFlow(flowExtra *FlowExtra, meta *MetaPacket) bool { // return: closed
	taggedFlow := flowExtra.taggedFlow
	flags := uint8(0)
	if meta.TcpData != nil {
		flags = meta.TcpData.Flags
	}
	taggedFlow.FlowMetricsPeers[meta.Direction].TCPFlags |= flags
	m.updateFlow(flowExtra, meta)

	m.updateTCPDirection(meta, flags, flowExtra, false)
	flowExtra.setMetaPacketActiveService(meta)

	if StatePreprocess(meta, flags) || meta.Invalid {
		flowExtra.timeout = exceptionTimeout
		flowExtra.flowState = FLOW_STATE_EXCEPTION
		return false
	}
	return m.updateFlowStateMachine(flowExtra, flags, meta.Direction == SERVER_TO_CLIENT)
}

func (m *FlowMap) updateTCPDirection(meta *MetaPacket, flags uint8, flowExtra *FlowExtra, isFirstPacket bool) {
	srcKey := ServiceKey(int16(meta.EndpointData.SrcInfo.L3EpcId), meta.IpSrc, meta.PortSrc)
	dstKey := ServiceKey(int16(meta.EndpointData.DstInfo.L3EpcId), meta.IpDst, meta.PortDst)

	srcScore, dstScore := m.tcpServiceTable.GetTCPScore(isFirstPacket, flags, srcKey, dstKey)
	if meta.Direction == SERVER_TO_CLIENT {
		srcScore, dstScore = dstScore, srcScore
	}
	if !IsClientToServer(srcScore, dstScore) {
		flowExtra.reverseFlow()
		flowExtra.reversed = !flowExtra.reversed
		meta.Direction = (CLIENT_TO_SERVER + SERVER_TO_CLIENT) - meta.Direction // reverse
	}
	flowExtra.taggedFlow.Flow.IsActiveService = IsActiveService(srcScore, dstScore)
}
