use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::str;

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
            rpc::tars_p::{proto, types},
            AppProtoHead, L7ResponseStatus, LogMessageType,
        },
        Error,
    },
    utils::bytes::{read_u16_be, read_u32_be},
    HttpLog,
};

#[derive(Serialize, Debug, Default, Clone)]
pub struct TarsInfo {
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
    #[serde(skip_serializing_if = "Option::is_none")]
    ret_desc: Option<String>,

    #[serde(rename = "request_id", skip_serializing_if = "Option::is_none")]
    request_id: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    servant_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    func_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<i16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    packet_type: Option<i8>,
}

#[derive(Default)]
pub struct TarsLog {
    perf_stats: Option<L7PerfStats>,
}

impl From<TarsInfo> for L7ProtocolSendLog {
    fn from(info: TarsInfo) -> Self {
        let flags = match info.is_tls {
            true => EbpfFlags::TLS.bits(),
            false => EbpfFlags::NONE.bits(),
        };

        let endpoint = info.get_endpoint();
        let version: proto::IVersion = info
            .version
            .map_or(proto::IVersion::Unknown, |v| proto::IVersion::from(v));
        let req_type: proto::CPackageType =
            info.packet_type.map_or(proto::CPackageType::Unknown, |v| {
                proto::CPackageType::from(v)
            });

        let log = L7ProtocolSendLog {
            flags,
            version: Some(String::from(version.as_str())),
            req_len: info.req_content_length,
            resp_len: info.resp_content_length,
            req: L7Request {
                req_type: String::from(req_type.as_str()),
                resource: info.servant_name.clone().unwrap_or_default(),
                endpoint: endpoint.unwrap_or_default(),
                ..Default::default()
            },
            resp: L7Response {
                status: info.status,
                code: info.ret,
                exception: info.ret_desc.unwrap_or_default(),
                ..Default::default()
            },
            trace_info: Some(TraceInfo {
                trace_id: info.trace_id,
                span_id: info.span_id,
                ..Default::default()
            }),
            ext_info: Some(ExtendedInfo {
                request_id: info.request_id,
                rpc_service: info.servant_name,
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

impl L7ProtocolInfoInterface for TarsInfo {
    fn is_tls(&self) -> bool {
        self.is_tls
    }

    fn session_id(&self) -> Option<u32> {
        self.request_id
    }

    fn app_proto_head(&self) -> Option<AppProtoHead> {
        Some(AppProtoHead {
            proto: L7Protocol::Tars,
            msg_type: self.msg_type,
            rrt: self.rrt,
        })
    }

    fn get_endpoint(&self) -> Option<String> {
        let servant_name = self.servant_name.as_ref().map(|s| s.as_str()).unwrap_or("");
        let func_name = self.func_name.as_ref().map(|s| s.as_str()).unwrap_or("");
        if servant_name.is_empty() || func_name.is_empty() {
            return Some("".to_string());
        }
        Some(format!("/{}/{}", servant_name, func_name))
    }

    fn merge_log(&mut self, other: &mut L7ProtocolInfo) -> Result<()> {
        if let (left, L7ProtocolInfo::TarsInfo(right)) = (self, other) {
            match right.msg_type {
                LogMessageType::Request => {
                    if right.req_content_length.is_some() {
                        left.req_content_length = right.req_content_length;
                    }
                    if right.servant_name.is_some() {
                        left.servant_name = right.servant_name.clone();
                    }
                    if right.func_name.is_some() {
                        left.func_name = right.func_name.clone();
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
                    if right.ret_desc.is_some() {
                        left.ret_desc = right.ret_desc.clone();
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
                left.trace_id = right.trace_id.clone();
            }
            if right.span_id.is_some() {
                left.span_id = right.span_id.clone();
            }
            if right.version.is_some() {
                left.version = right.version;
            }
            if right.packet_type.is_some() {
                left.packet_type = right.packet_type;
            }
            if right.request_id.is_some() {
                left.request_id = right.request_id;
            }
        }

        Ok(())
    }
}

impl L7ProtocolParserInterface for TarsLog {
    fn check_payload(&mut self, payload: &[u8], param: &ParseParam) -> bool {
        if !param.ebpf_type.is_raw_protocol() {
            return false;
        }
        if param.l4_protocol != IpProtocol::TCP {
            return false;
        }
        // RequestPacket 有 10 个 Tag，ResponsePacket 有 9 个
        // 假设字段全部都是 Empty，至少需要空间 1 bytes(Tag + Empty) * 9 = 9 bytes
        // 加上前 4 字节表示长度，payload 最小长度为 9 + 4 = 13 bytes
        if payload.len() < 13 {
            return false;
        }

        // 可能的几种
        // iVersion
        // 0001(Tag)0000(Type)0000 0001(Byte) - 10 01 -
        // 0001(Tag)0000(Type)0000 0002(Byte) - 10 02
        // 0001(Tag)0000(Type)0000 0003(Byte) - 10 03
        // 0001(Tag)0001(Type)0000 0001 0000 0001 - 11 01 01
        // 0001(Tag)0001(Type)0000 0111 1101 1011 - 11 07 db
        // cPackageType
        // 0002(Tag)1100(Empty) - 2c
        // 0002(Tag)0000(Type)0000 0001(Byte) - 20 01
        if payload[4] != 0x10 && payload[4] != 0x11 {
            return false;
        }
        let iversion_flag = read_u16_be(&payload[5..7]);
        if iversion_flag != 0x101 && iversion_flag != 0x7db && (payload[5] > 3 || payload[5] == 0) {
            return false;
        }
        if payload[6] != 0x2c && payload[6] != 0x20 && payload[7] != 0x2c && payload[7] != 0x20 {
            return false;
        }
        true
    }

    fn parse_payload(&mut self, payload: &[u8], param: &ParseParam) -> Result<L7ParseResult> {
        if self.perf_stats.is_none() && param.parse_perf {
            self.perf_stats = Some(L7PerfStats::default())
        };

        let mut info = TarsInfo::default();
        self.parse(payload, param, &mut info)?;

        info.is_tls = param.is_tls();

        if param.parse_log {
            Ok(L7ParseResult::Single(L7ProtocolInfo::TarsInfo(info)))
        } else {
            Ok(L7ParseResult::None)
        }
    }

    fn perf_stats(&mut self) -> Option<L7PerfStats> {
        self.perf_stats.take()
    }

    fn protocol(&self) -> L7Protocol {
        L7Protocol::Tars
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

impl TarsLog {
    fn set_status(&mut self, info: &mut TarsInfo, param: &ParseParam) {
        let success_ret_code = proto::IRet::ServerSuccess as i32;
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
        info: &mut TarsInfo,
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

    fn on_context(
        &mut self,
        info: &mut TarsInfo,
        config: &L7LogDynamicConfig,
        proto_map: &HashMap<u8, types::Value>,
        tag: u8,
    ) -> Result<()> {
        if let Some(types::Value::Map(map)) = proto_map.get(&tag) {
            for (k, v) in map.iter() {
                if let types::Value::Bytes(v) = v {
                    self.on_header(k.as_bytes(), v, info, config)?;
                }
            }
        }
        Ok(())
    }

    fn parse(&mut self, payload: &[u8], param: &ParseParam, info: &mut TarsInfo) -> Result<()> {
        let Some(config) = param.parse_config else {
            return Err(Error::TarsLogParseFailed);
        };
        let length = read_u32_be(&payload[..4]);
        match param.direction {
            PacketDirection::ClientToServer => {
                info.req_content_length = Some(length);
                info.msg_type = LogMessageType::Request;
                self.perf_stats.as_mut().map(|p| p.inc_req());
                let proto_map = proto::JceBuf::new(
                    &payload[4..], &[3, 7, 8, 10]
                ).read_to_hashmap();
                info.version = Some(proto::get_proto_version(&proto_map, proto::TAG_REQ_VERSION));
                info.packet_type = Some(proto::get_proto_package_type(&proto_map, proto::TAG_REQ_PACKAGE_TYPE));
                info.request_id = Some(proto::get_proto_request_id(&proto_map, proto::TAG_REQ_REQUEST_ID));
                info.servant_name = Some(proto::get_proto_string(&proto_map, proto::TAG_REQ_SERVANT_NAME));
                info.func_name = Some(proto::get_proto_string(&proto_map, proto::TAG_REQ_FUNC_NAME));
                self.on_context(info, &config.l7_log_dynamic, &proto_map, proto::TAG_REQ_CONTEXT)?;
            }
            PacketDirection::ServerToClient => {
                info.resp_content_length = Some(length);
                info.msg_type = LogMessageType::Response;
                self.perf_stats.as_mut().map(|p| p.inc_resp());
                let proto_map = proto::JceBuf::new(
                    &payload[4..], &[4, 6, 7]
                ).read_to_hashmap();
                info.version = Some(proto::get_proto_version(&proto_map, proto::TAG_RESP_VERSION));
                info.packet_type = Some(proto::get_proto_package_type(&proto_map, proto::TAG_RESP_PACKAGE_TYPE));
                info.request_id = Some(proto::get_proto_request_id(&proto_map, proto::TAG_RESP_REQUEST_ID));
                info.ret = Some(proto::get_proto_ret(&proto_map));
                info.ret_desc = Some(proto::get_proto_string(&proto_map, proto::TAG_RESP_RESULT_DESC));
                self.on_context(info, &config.l7_log_dynamic, &proto_map, proto::TAG_REQ_CONTEXT)?;
                self.set_status(info, param);
            }
        }

        info.cal_rrt(param, None).map(|rrt| {
            info.rrt = rrt;
            self.perf_stats.as_mut().map(|p| p.update_rrt(rrt));
        });

        Ok(())
    }
}
