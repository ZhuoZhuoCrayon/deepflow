#[path = "trpc/trpc.proto.rs"]
mod trpc_policy;

use prost::Message;
use serde::Serialize;
use std::collections::HashMap;
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
    flow_generator::{
        Error,
        error::Result,
        protocol_logs::{
            pb_adapter::{
                ExtendedInfo, KeyVal, L7ProtocolSendLog, L7Request, L7Response, TraceInfo,
            },
            AppProtoHead, L7ResponseStatus, LogMessageType,
        },
    },
    utils::bytes::{read_u16_be, read_u32_be},
};

use log::warn;

#[derive(Serialize, Debug, Default, Clone)]
pub struct TrpcInfo {
    #[serde(skip)]
    is_tls: bool,
    #[serde(skip)]
    rrt: u64,

    msg_type: LogMessageType,

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
                req_type: String::from("POST"),
                resource: info.callee.unwrap_or_default(),
                endpoint: endpoint.unwrap_or_default(),
                ..Default::default()
            },
            resp: L7Response {
                status: L7ResponseStatus::Ok,
                code: info.ret,
                ..Default::default()
            },
            trace_info: Some(TraceInfo {
                trace_id: info.trace_id,
                span_id: info.span_id,
                ..Default::default()
            }),
            ext_info: Some(ExtendedInfo {
                request_id: info.stream_id,
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

    fn merge_log(&mut self, other: &mut L7ProtocolInfo) -> Result<()> {
        if let (left, L7ProtocolInfo::TrpcInfo(right)) = (self, other) {
            match right.msg_type {
                LogMessageType::Request => {
                    if right.req_content_length.is_some() {
                        left.req_content_length = right.resp_content_length
                    }
                    if right.caller.is_some() {
                        left.caller = right.caller.clone()
                    }
                    if right.callee.is_some() {
                        left.callee = right.callee.clone()
                    }
                    if right.func.is_some() {
                        left.func = right.func.clone()
                    }
                }
                LogMessageType::Response => {
                    if right.resp_content_length.is_some() {
                        left.resp_content_length = right.resp_content_length
                    }
                    if right.status != left.status {
                        left.status = right.status
                    }
                    if right.ret.is_some() {
                        left.ret = right.ret
                    }
                }
                _ => {}
            }
            left.attributes.append(&mut right.attributes);
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

        warn!("[trpc] start to parse_payload");

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
        let ret_code = info.ret.unwrap_or_default();
        if ret_code == TrpcRetCode::TrpcInvokeSuccess as i32 {
            info.status = L7ResponseStatus::Ok
        } else if (ret_code >= TrpcRetCode::TrpcServerDecodeErr as i32
            && ret_code <= TrpcRetCode::TrpcServerValidateErr as i32)
            || (ret_code >= TrpcRetCode::TrpcStreamServerNetworkErr as i32
                && ret_code <= TrpcRetCode::TrpcStreamServerIdleTimeoutErr as i32)
        {
            self.perf_stats.as_mut().map(|p| p.inc_resp_err());
            info.status = L7ResponseStatus::ServerError
        } else if (ret_code >= TrpcRetCode::TrpcClientInvokeTimeoutErr as i32
            && ret_code <= TrpcRetCode::TrpcClientReadFrameErr as i32)
            || ret_code >= TrpcRetCode::TrpcStreamClientNetworkErr as i32
        {
            self.perf_stats.as_mut().map(|p| p.inc_req());
            info.status = L7ResponseStatus::ClientError
        } else {
            match param.direction {
                PacketDirection::ClientToServer => {
                    self.perf_stats.as_mut().map(|p| p.inc_req());
                    info.status = L7ResponseStatus::ClientError
                }
                PacketDirection::ServerToClient => {
                    self.perf_stats.as_mut().map(|p| p.inc_resp_err());
                    info.status = L7ResponseStatus::ServerError
                }
            }
        }
    }

    fn on_header(&mut self, key: &[u8], val: &[u8], info: &mut TrpcInfo) -> Result<()> {
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
        info.attributes.push(KeyVal {
            key: key.to_owned(),
            val: val.to_owned(),
        });
        Ok(())
    }

    fn on_trans_info(
        &mut self,
        trans_info: HashMap<String, Vec<u8>>,
        info: &mut TrpcInfo,
    ) -> Result<()> {
        for (key, value) in trans_info {
            self.on_header(key.as_bytes(), &value, info)?;
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
    ) -> Result<()> {
        match param.direction {
            PacketDirection::ClientToServer => {
                let Some(req) = RequestProtocol::decode(&payload[16..16 + header_len as usize]).ok() else {
                    warn!("[trpc] failed to decode RequestProtocol, payload -> {:?}", &payload[16..16 + header_len as usize]);
                    return Err(Error::TrpcLogParseFailed);
                };
                info.msg_type = LogMessageType::Request;

                info.caller = Some(String::from_utf8(req.caller).unwrap_or_default());
                info.callee = Some(String::from_utf8(req.callee).unwrap_or_default());
                info.func = Some(String::from_utf8(req.func).unwrap_or_default());
                info.req_content_length = Some(total_len - header_len - 16);
                warn!("[trpc] caller -> {:?}, callee -> {:?}, func -> {:?}", info.caller, info.callee, info.func);
                self.on_trans_info(req.trans_info, info)?;
                warn!("[trpc] attributes -> {:?}", info.attributes);
            }
            PacketDirection::ServerToClient => {
                let Some(resp) = ResponseProtocol::decode(&payload[16..16 + header_len as usize]).ok() else {
                    warn!("[trpc] failed to decode ResponseProtocol, payload -> {:?}", &payload[16..16 + header_len as usize]);
                    return Err(Error::TrpcLogParseFailed);
                };
                info.msg_type = LogMessageType::Response;
                info.ret = Some(resp.ret);
                info.resp_content_length = Some(total_len - header_len - 16);

                warn!("[trpc] msg_type -> {:?}, ret -> {:?}, resp_content_length -> {:?}", info.msg_type, info.ret, info.resp_content_length);

                self.set_status(info, param);
                self.on_trans_info(resp.trans_info, info)?;

                warn!("[trpc] attributes -> {:?}, status -> {:?}", info.attributes, info.status);
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
    ) -> Result<()> {
        let Some(init_meta) = TrpcStreamInitMeta::decode(&payload[16..total_len as usize]).ok() else {
            return Err(Error::TrpcLogParseFailed);
        };
        if init_meta.request_meta.is_some() {
            info.msg_type = LogMessageType::Request;
            if let Some(request_meta) = init_meta.request_meta {
                info.caller = Some(String::from_utf8(request_meta.caller).unwrap_or_default());
                info.callee = Some(String::from_utf8(request_meta.callee).unwrap_or_default());
                info.func = Some(String::from_utf8(request_meta.func).unwrap_or_default());
                self.on_trans_info(request_meta.trans_info, info)?;
            } else if let Some(response_meta) = init_meta.response_meta {
                // 成功表示流将持续，只有失败才认为流结束
                if response_meta.ret != TrpcRetCode::TrpcInvokeSuccess as i32 {
                    info.msg_type = LogMessageType::Response;
                    info.ret = Some(response_meta.ret);
                    self.set_status(info, param);
                }
            }
        }
        Ok(())
    }

    fn handle_stream_close(
        &mut self,
        payload: &[u8],
        total_len: u32,
        param: &ParseParam,
        info: &mut TrpcInfo,
    ) -> Result<()> {
        let Some(close_meta) = TrpcStreamCloseMeta::decode(&payload[16..total_len as usize]).ok() else {
            return Err(Error::TrpcLogParseFailed);
        };

        // 以服务端 close 作为最终响应
        if param.direction == PacketDirection::ServerToClient {
            info.msg_type = LogMessageType::Response;
        }

        if close_meta.close_type == 1 {
            if close_meta.ret == TrpcRetCode::TrpcInvokeSuccess as i32 {
                info.ret = Some(TrpcRetCode::TrpcStreamUnknownErr as i32)
            } else {
                info.ret = Some(close_meta.ret)
            }
        } else {
            // 以服务端 close 作为最终响应
            if param.direction == PacketDirection::ServerToClient {
                info.ret = Some(close_meta.ret);
            }
        }
        self.set_status(info, param);
        Ok(())
    }

    fn parse(&mut self, payload: &[u8], param: &ParseParam, info: &mut TrpcInfo) -> Result<()> {
        info.data_frame_type = Some(payload[2]);
        info.stream_frame_type = Some(payload[3]);

        warn!("[trpc] data_frame_type -> {:?}, stream_frame_type -> {:?}", info.data_frame_type, info.stream_frame_type);

        let total_len = read_u32_be(&payload[4..8]) as usize;
        let header_len = read_u16_be(&payload[8..10]) as usize;
        info.stream_id = Some(read_u32_be(&payload[10..14]));

        warn!("[trpc] total_len -> {:?}, header_len -> {:?}, stream_id -> {:?}", total_len, header_len, info.stream_id);

        // 根据不同模式解析 body
        match info.data_frame_type {
            Some(d) if d == TrpcDataFrameType::TrpcUnaryFrame as u8 => {
                self.handle_unary(payload, total_len as u32, header_len as u32, param, info)?;
            }
            Some(d) if d == TrpcDataFrameType::TrpcStreamFrame as u8 => {
                match info.stream_frame_type {
                    Some(s) if s == TrpcStreamFrameType::TrpcStreamFrameInit as u8 => {
                        self.handle_stream_init(payload, total_len as u32, param, info)?;
                    }
                    Some(s) if s == TrpcStreamFrameType::TrpcStreamFrameClose as u8 => {
                        self.handle_stream_close(payload, total_len as u32, param, info)?;
                    }
                    _ => {}
                }
            }
            _ => {}
        }

        info.cal_rrt(param, None).map(|rrt| {
            info.rrt = rrt;
            self.perf_stats.as_mut().map(|p| p.update_rrt(rrt));
        });

        Ok(())
    }
}
