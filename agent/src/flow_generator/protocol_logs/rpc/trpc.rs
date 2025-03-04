#[path = "trpc/trpc.proto.rs"]
mod trpc_policy;

use prost::Message;
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::str;
use trpc_policy::{
    RequestProtocol, ResponseProtocol, TrpcDataFrameType, TrpcRetCode, TrpcStreamCloseMeta,
    TrpcStreamFrameType, TrpcStreamInitMeta,
};

use crate::{
    common::{
        enums::IpProtocol,
        flow::{L7PerfStats, L7Protocol, PacketDirection},
        l7_protocol_info::{L7ProtocolInfo, L7ProtocolInfoInterface},
        l7_protocol_log::{L7ParseResult, L7ProtocolParserInterface, ParseParam},
        meta_packet::EbpfFlags,
    },
    config::handler::L7LogDynamicConfig,
    flow_generator::{
        error::Result,
        protocol_logs::{
            pb_adapter::{
                ExtendedInfo, KeyVal, L7ProtocolSendLog, L7Request, L7Response, TraceInfo,
            },
            AppProtoHead, L7ResponseStatus, LogMessageType,
        },
        Error,
    },
    utils::bytes::{read_u16_be, read_u32_be},
    HttpLog,
};

#[derive(Serialize, Debug, Default, Clone)]
pub struct TrpcInfo {
    #[serde(skip)]
    is_tls: bool,
    #[serde(skip)]
    rrt: u64,

    msg_type: LogMessageType,
    #[serde(skip)]
    is_req_end: bool,
    #[serde(skip)]
    is_resp_end: bool,

    #[serde(skip_serializing_if = "Option::is_none")]
    trace_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    span_id: Option<String>,
    #[serde(skip)]
    attributes: Vec<KeyVal>,

    #[serde(rename = "request_length", skip_serializing_if = "Option::is_none")]
    req_content_length: Option<u32>,
    #[serde(rename = "response_length", skip_serializing_if = "Option::is_none")]
    resp_content_length: Option<u32>,

    #[serde(rename = "response_status")]
    status: L7ResponseStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    ret: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    func_ret: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    err_msg: Option<String>,

    #[serde(rename = "request_id", skip_serializing_if = "Option::is_none")]
    stream_id: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    caller: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    callee: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    func: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    data_frame_type: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    stream_frame_type: Option<u8>,
}

#[derive(Default)]
pub struct TrpcLog {
    perf_stats: Option<L7PerfStats>,
}

impl From<TrpcInfo> for L7ProtocolSendLog {
    fn from(info: TrpcInfo) -> Self {
        let flags = match info.is_tls {
            true => EbpfFlags::TLS.bits(),
            false => EbpfFlags::NONE.bits(),
        };

        let endpoint = info.get_endpoint();

        let log = L7ProtocolSendLog {
            flags,
            req_len: info.req_content_length,
            resp_len: info.resp_content_length,
            req: L7Request {
                req_type: match info.data_frame_type {
                    Some(0) => String::from("UNARY"),
                    Some(1) => String::from("STREAM"),
                    _ => String::from("UNKNOWN"),
                },
                resource: info.callee.clone().unwrap_or_default(),
                endpoint: endpoint.unwrap_or_default(),
                ..Default::default()
            },
            resp: L7Response {
                status: info.status,
                code: info.ret,
                exception: info.err_msg.unwrap_or_default(),
                ..Default::default()
            },
            trace_info: Some(TraceInfo {
                trace_id: info.trace_id,
                span_id: info.span_id,
                ..Default::default()
            }),
            ext_info: Some(ExtendedInfo {
                request_id: info.stream_id,
                rpc_service: info.callee,
                attributes: {
                    if info.attributes.is_empty() {
                        None
                    } else {
                        Some(info.attributes)
                    }
                },
                ..Default::default()
            }),
            ..Default::default()
        };
        log
    }
}

impl L7ProtocolInfoInterface for TrpcInfo {
    fn is_tls(&self) -> bool {
        self.is_tls
    }

    fn session_id(&self) -> Option<u32> {
        self.stream_id
    }

    fn app_proto_head(&self) -> Option<AppProtoHead> {
        Some(AppProtoHead {
            proto: L7Protocol::Trpc,
            msg_type: self.msg_type,
            rrt: self.rrt,
        })
    }

    fn get_endpoint(&self) -> Option<String> {
        self.func.clone()
    }

    fn is_req_resp_end(&self) -> (bool, bool) {
        return (self.is_req_end, self.is_resp_end);
    }

    fn need_merge(&self) -> bool {
        return match self.data_frame_type {
            // 流式场景是多帧传输，需要聚合
            Some(s) if s == TrpcDataFrameType::TrpcStreamFrame as u8 => true,
            _ => false,
        };
    }

    fn merge_log(&mut self, other: &mut L7ProtocolInfo) -> Result<()> {
        if let (left, L7ProtocolInfo::TrpcInfo(right)) = (self, other) {
            match right.msg_type {
                LogMessageType::Request => {
                    if right.req_content_length.is_some() {
                        left.req_content_length = right.req_content_length;
                    }
                    if right.caller.is_some() {
                        left.caller = right.caller.clone();
                    }
                    if right.callee.is_some() {
                        left.callee = right.callee.clone();
                    }
                    if right.func.is_some() {
                        left.func = right.func.clone();
                    }
                    if right.is_req_end {
                        left.is_req_end = true;
                    }
                }
                LogMessageType::Response => {
                    if right.resp_content_length.is_some() {
                        left.resp_content_length = right.resp_content_length;
                    }
                    if right.status != left.status {
                        left.status = right.status;
                    }
                    if right.ret.is_some() {
                        left.ret = right.ret;
                    }
                    if right.func_ret.is_some() {
                        left.func_ret = right.ret;
                    }
                    if right.err_msg.is_some() {
                        left.err_msg = right.err_msg.clone();
                    }
                    if right.is_resp_end {
                        left.is_resp_end = true;
                    }
                }
                _ => {}
            }

            let mut existing_keys: HashSet<_> =
                left.attributes.iter().map(|kv| kv.key.clone()).collect();
            let new_attributes: Vec<_> = right
                .attributes
                .drain(..)
                .filter(|kv| existing_keys.insert(kv.key.clone()))
                .collect();
            left.attributes.extend(new_attributes);

            if right.trace_id.is_some() {
                left.trace_id = right.trace_id.clone()
            }
            if right.span_id.is_some() {
                left.span_id = right.span_id.clone()
            }
        }

        Ok(())
    }
}

impl L7ProtocolParserInterface for TrpcLog {
    fn check_payload(&mut self, payload: &[u8], param: &ParseParam) -> bool {
        if !param.ebpf_type.is_raw_protocol() {
            return false;
        }
        if param.l4_protocol != IpProtocol::TCP {
            return false;
        }
        if payload.len() < 16 {
            return false;
        }
        let magic = read_u16_be(&payload[0..2]);
        if magic != 0x930 {
            return false;
        }
        true
    }

    fn parse_payload(&mut self, payload: &[u8], param: &ParseParam) -> Result<L7ParseResult> {
        if self.perf_stats.is_none() && param.parse_perf {
            self.perf_stats = Some(L7PerfStats::default())
        };

        let mut info = TrpcInfo::default();
        self.parse(payload, param, &mut info)?;

        info.is_tls = param.is_tls();

        if param.parse_log {
            Ok(L7ParseResult::Single(L7ProtocolInfo::TrpcInfo(info)))
        } else {
            Ok(L7ParseResult::None)
        }
    }

    fn perf_stats(&mut self) -> Option<L7PerfStats> {
        self.perf_stats.take()
    }

    fn protocol(&self) -> L7Protocol {
        L7Protocol::Trpc
    }

    fn parsable_on_udp(&self) -> bool {
        false
    }

    fn reset(&mut self) {
        let mut s = Self::default();
        s.perf_stats = self.perf_stats.take();
        *self = s;
    }
}

impl TrpcLog {
    fn set_status(&mut self, info: &mut TrpcInfo, param: &ParseParam) {
        let success_ret_code = TrpcRetCode::TrpcInvokeSuccess as i32;
        if info.ret == Some(success_ret_code) && info.func_ret.is_some() {
            info.ret = info.func_ret
        }

        match info.ret {
            Some(ret) if ret == success_ret_code => {
                info.status = L7ResponseStatus::Ok;
            }
            _ => match param.direction {
                PacketDirection::ClientToServer => {
                    self.perf_stats.as_mut().map(|p| p.inc_req_err());
                    info.status = L7ResponseStatus::ClientError;
                }
                PacketDirection::ServerToClient => {
                    self.perf_stats.as_mut().map(|p| p.inc_resp_err());
                    info.status = L7ResponseStatus::ServerError;
                }
            },
        }
    }

    fn on_header(
        &mut self,
        key: &[u8],
        val: &[u8],
        info: &mut TrpcInfo,
        config: &L7LogDynamicConfig,
    ) -> Result<()> {
        // key must be valid utf8
        let Ok(key) = str::from_utf8(key) else {
            return Ok(());
        };
        if !key.is_ascii() {
            return Ok(());
        }
        // value must be valid utf8 from here
        let Ok(val) = str::from_utf8(val) else {
            return Ok(());
        };

        match key {
            "tracestate" => return Ok(()),
            _ => {}
        }

        let mut need_skip = false;
        if config.is_trace_id(key) {
            info.trace_id = HttpLog::decode_id(val, key, HttpLog::TRACE_ID);
            need_skip = true
        }
        if config.is_span_id(key) {
            info.span_id = HttpLog::decode_id(val, key, HttpLog::SPAN_ID);
            need_skip = true
        }

        if !need_skip {
            info.attributes.push(KeyVal {
                key: key.to_owned(),
                val: val.to_owned(),
            });
        }

        Ok(())
    }

    fn on_trans_info(
        &mut self,
        trans_info: HashMap<String, Vec<u8>>,
        info: &mut TrpcInfo,
        config: &L7LogDynamicConfig,
    ) -> Result<()> {
        for (key, value) in trans_info {
            self.on_header(key.as_bytes(), &value, info, config)?;
        }
        Ok(())
    }

    fn handle_unary(
        &mut self,
        payload: &[u8],
        total_len: u32,
        header_len: u32,
        param: &ParseParam,
        info: &mut TrpcInfo,
        config: &L7LogDynamicConfig,
    ) -> Result<()> {
        match param.direction {
            PacketDirection::ClientToServer => {
                let Some(req) = RequestProtocol::decode(&payload[16..16 + header_len as usize]).ok() else {
                    return Err(Error::TrpcLogParseFailed);
                };
                info.is_req_end = true;
                info.msg_type = LogMessageType::Request;
                self.perf_stats.as_mut().map(|p| p.inc_req());

                // stream id for streaming rpc, request id for unary rpc
                info.stream_id = Some(req.request_id);
                info.caller = Some(String::from_utf8(req.caller).unwrap_or_default());
                info.callee = Some(String::from_utf8(req.callee).unwrap_or_default());
                info.func = Some(String::from_utf8(req.func).unwrap_or_default());
                info.req_content_length = Some(total_len - header_len - 16);

                self.on_trans_info(req.trans_info, info, config)?;
            }
            PacketDirection::ServerToClient => {
                let Some(resp) = ResponseProtocol::decode(&payload[16..16 + header_len as usize]).ok() else {
                    return Err(Error::TrpcLogParseFailed);
                };
                info.is_resp_end = true;
                info.msg_type = LogMessageType::Response;
                self.perf_stats.as_mut().map(|p| p.inc_resp());

                // stream id for streaming rpc, request id for unary rpc
                info.stream_id = Some(resp.request_id);
                info.ret = Some(resp.ret);
                info.func_ret = Some(resp.func_ret);
                info.err_msg = Some(String::from_utf8(resp.error_msg).unwrap_or_default());
                info.resp_content_length = Some(total_len - header_len - 16);

                self.set_status(info, param);
                self.on_trans_info(resp.trans_info, info, config)?;
            }
        }
        Ok(())
    }

    fn handle_stream_init(
        &mut self,
        payload: &[u8],
        total_len: u32,
        param: &ParseParam,
        info: &mut TrpcInfo,
        config: &L7LogDynamicConfig,
    ) -> Result<()> {
        if payload.len() < total_len as usize {
            return Err(Error::TrpcLogParseFailed);
        }
        let Some(init_meta) = TrpcStreamInitMeta::decode(&payload[16..total_len as usize]).ok() else {
            return Err(Error::TrpcLogParseFailed);
        };

        if let Some(request_meta) = init_meta.request_meta {
            info.is_req_end = true;
            info.msg_type = LogMessageType::Request;
            self.perf_stats.as_mut().map(|p| p.inc_req());
            info.caller = Some(String::from_utf8(request_meta.caller).unwrap_or_default());
            info.callee = Some(String::from_utf8(request_meta.callee).unwrap_or_default());
            info.func = Some(String::from_utf8(request_meta.func).unwrap_or_default());
            info.req_content_length = Some(total_len - 16);
            self.on_trans_info(request_meta.trans_info, info, config)?;
        } else if let Some(response_meta) = init_meta.response_meta {
            // 成功表示流将持续，只有失败才认为流结束
            if response_meta.ret != TrpcRetCode::TrpcInvokeSuccess as i32 {
                info.is_resp_end = true;
                info.msg_type = LogMessageType::Response;
                self.perf_stats.as_mut().map(|p| p.inc_resp());

                info.ret = Some(response_meta.ret);
                info.err_msg = Some(String::from_utf8(response_meta.error_msg).unwrap_or_default());
                self.set_status(info, param);
            }
        } else {
            return Err(Error::TrpcLogParseFailed);
        }
        Ok(())
    }

    fn handle_stream_close(
        &mut self,
        payload: &[u8],
        total_len: u32,
        param: &ParseParam,
        info: &mut TrpcInfo,
        config: &L7LogDynamicConfig,
    ) -> Result<()> {
        if payload.len() < total_len as usize {
            return Err(Error::TrpcLogParseFailed);
        }

        let Some(close_meta) = TrpcStreamCloseMeta::decode(&payload[16..total_len as usize]).ok() else {
            return Err(Error::TrpcLogParseFailed);
        };

        info.ret = Some(close_meta.ret);
        info.func_ret = Some(close_meta.func_ret);
        info.err_msg = Some(String::from_utf8(close_meta.msg).unwrap_or_default());
        self.on_trans_info(close_meta.trans_info, info, config)?;

        match close_meta.close_type {
            1 => {
                if close_meta.ret == TrpcRetCode::TrpcInvokeSuccess as i32 {
                    info.ret = Some(TrpcRetCode::TrpcStreamUnknownErr as i32);
                }
                self.set_status(info, param);
            }
            _ => {
                // 以服务端 close 作为最终响应
                if param.direction == PacketDirection::ServerToClient {
                    info.resp_content_length = Some(total_len - 16);
                    self.set_status(info, param);
                }
            }
        }

        if param.direction == PacketDirection::ServerToClient {
            // 以服务端 close 作为最终响应
            info.is_resp_end = true;
            info.msg_type = LogMessageType::Response;
            self.perf_stats.as_mut().map(|p| p.inc_resp());
        } else {
            info.msg_type = LogMessageType::Request;
        }

        Ok(())
    }

    fn parse(&mut self, payload: &[u8], param: &ParseParam, info: &mut TrpcInfo) -> Result<()> {
        let Some(config) = param.parse_config else {
            return Err(Error::TrpcLogParseFailed);
        };

        info.data_frame_type = Some(payload[2]);
        info.stream_frame_type = Some(payload[3]);

        let total_len = read_u32_be(&payload[4..8]) as usize;
        let header_len = read_u16_be(&payload[8..10]) as usize;
        info.stream_id = Some(read_u32_be(&payload[10..14]));

        // 根据不同模式解析 body
        match info.data_frame_type {
            Some(d) if d == TrpcDataFrameType::TrpcUnaryFrame as u8 => {
                self.handle_unary(
                    payload,
                    total_len as u32,
                    header_len as u32,
                    param,
                    info,
                    &config.l7_log_dynamic,
                )?;
            }
            Some(d) if d == TrpcDataFrameType::TrpcStreamFrame as u8 => {
                match info.stream_frame_type {
                    Some(s) if s == TrpcStreamFrameType::TrpcStreamFrameInit as u8 => {
                        self.handle_stream_init(
                            payload,
                            total_len as u32,
                            param,
                            info,
                            &config.l7_log_dynamic,
                        )?;
                    }
                    Some(s) if s == TrpcStreamFrameType::TrpcStreamFrameClose as u8 => {
                        self.handle_stream_close(
                            payload,
                            total_len as u32,
                            param,
                            info,
                            &config.l7_log_dynamic,
                        )?;
                    }
                    Some(s) if s == TrpcStreamFrameType::TrpcStreamFrameData as u8 => {
                        info.resp_content_length = Some(total_len as u32 - 16);
                    }
                    _ => return Err(Error::TrpcLogParseFailed),
                }
            }
            _ => return Err(Error::TrpcLogParseFailed),
        }

        if info.is_req_end || info.is_resp_end {
            info.cal_rrt(param, None).map(|rrt| {
                info.rrt = rrt;
                self.perf_stats.as_mut().map(|p| p.update_rrt(rrt));
            });
        }

        Ok(())
    }
}
