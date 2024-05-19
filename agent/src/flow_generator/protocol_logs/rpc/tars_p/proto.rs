use super::errors::{DecodeError, Result};
use super::types;
use std::collections::{HashMap, HashSet};

pub const TAG_REQ_VERSION: u8 = 1;
pub const TAG_REQ_PACKAGE_TYPE: u8 = 2;
pub const TAG_REQ_REQUEST_ID: u8 = 4;
pub const TAG_REQ_SERVANT_NAME: u8 = 5;
pub const TAG_REQ_FUNC_NAME: u8 = 6;
pub const TAG_REQ_CONTEXT: u8 = 9;
pub const TAG_RESP_VERSION: u8 = 1;
pub const TAG_RESP_PACKAGE_TYPE: u8 = 2;
pub const TAG_RESP_REQUEST_ID: u8 = 3;
pub const TAG_RESP_RET: u8 = 5;
pub const TAG_RESP_RESULT_DESC: u8 = 8;
pub const TAG_RESP_CONTEXT: u8 = 9;

#[repr(i16)]
#[derive(Debug, PartialEq, Eq)]
pub enum IVersion {
    Jce = 1,
    Wup = 2,
    Wup2 = 3,
    Json = 257,
    SrfJson = 2011,
    Unknown = i16::MAX,
}

impl From<i16> for IVersion {
    fn from(num: i16) -> Self {
        match num {
            1 => IVersion::Jce,
            2 => IVersion::Wup,
            3 => IVersion::Wup2,
            257 => IVersion::Json,
            2011 => IVersion::SrfJson,
            _ => IVersion::Unknown,
        }
    }
}

impl IVersion {
    pub fn as_str(&self) -> &str {
        match self {
            IVersion::Jce => "JCE",
            IVersion::Wup => "WUP",
            IVersion::Wup2 => "WUP2",
            IVersion::Json => "JSON",
            IVersion::SrfJson => "SRFJSON",
            IVersion::Unknown => "UNKNOWN",
        }
    }
}

#[repr(i8)]
#[derive(Debug, PartialEq, Eq)]
pub enum CPackageType {
    // 普通调用
    Normal = 0,
    // 单向调用
    Oneway = 1,
    Unknown = i8::MAX,
}

impl From<i8> for CPackageType {
    fn from(num: i8) -> Self {
        match num {
            0 => CPackageType::Normal,
            1 => CPackageType::Oneway,
            _ => CPackageType::Unknown,
        }
    }
}

impl CPackageType {
    pub fn as_str(&self) -> &str {
        match self {
            CPackageType::Normal => "NORMAL",
            CPackageType::Oneway => "ONEWAY",
            CPackageType::Unknown => "UNKNOWN",
        }
    }
}

#[repr(i32)]
#[derive(Debug, PartialEq, Eq)]
pub enum IRet {
    // 服务器端处理成功
    ServerSuccess = 0,
    // 服务器端解码异常
    ServerDecodeErr = -1,
    // 服务器端编码异常
    ServerEncodeErr = -2,
    // 服务器端没有该函数
    ServerNoFuncErr = -3,
    // 服务器端没有该Servant对象
    ServerNoServantErr = -4,
    // 服务器端灰度状态不一致
    ServerResetGrid = -5,
    // 服务器队列超过限制
    ServerQueueTimeout = -6,
    // 调用超时
    InvokeTimeout = -7,
    // proxy 链接异常
    ProxyConnectErr = -8,
    // 服务器端超负载,超过队列长度
    ServerOverload = -9,
    // 客户端选路为空，服务不存在或者所有服务 down 掉了
    AdapterNull = -10,
    // 客户端按 set 规则调用非法
    InvokeByInvalidEset = -11,
    // 客户端解码异常
    ClientDecodeErr = -12,
    // 服务器端位置异常
    ServerUnknownErr = -99,
    CustomErr = i32::MAX,
}

impl From<i32> for IRet {
    fn from(num: i32) -> Self {
        match num {
            0 => IRet::ServerSuccess,
            -1 => IRet::ServerDecodeErr,
            -2 => IRet::ServerEncodeErr,
            -3 => IRet::ServerNoFuncErr,
            -4 => IRet::ServerNoServantErr,
            -5 => IRet::ServerResetGrid,
            -6 => IRet::ServerQueueTimeout,
            -7 => IRet::InvokeTimeout,
            -8 => IRet::ProxyConnectErr,
            -9 => IRet::ServerOverload,
            -10 => IRet::AdapterNull,
            -11 => IRet::InvokeByInvalidEset,
            -12 => IRet::ClientDecodeErr,
            -99 => IRet::ServerUnknownErr,
            _ => IRet::CustomErr,
        }
    }
}

impl IRet {
    pub fn as_str(&self) -> &str {
        match self {
            IRet::ServerSuccess => "ServerSuccess",
            IRet::ServerDecodeErr => "ServerDecodeErr",
            IRet::ServerEncodeErr => "ServerEncodeErr",
            IRet::ServerNoFuncErr => "ServerNoFuncErr",
            IRet::ServerNoServantErr => "ServerNoServantErr",
            IRet::ServerResetGrid => "ServerResetGrid",
            IRet::ServerQueueTimeout => "ServerQueueTimeout",
            IRet::InvokeTimeout => "InvokeTimeout",
            IRet::ProxyConnectErr => "ProxyConnectErr",
            IRet::ServerOverload => "ServerOverload",
            IRet::AdapterNull => "AdapterNull",
            IRet::InvokeByInvalidEset => "InvokeByInvalidEset",
            IRet::ClientDecodeErr => "ClientDecodeErr",
            IRet::ServerUnknownErr => "ServerUnknownErr",
            IRet::CustomErr => "CustomErr",
        }
    }
}

pub fn get_i32(v: &types::Value) -> i32 {
    match v {
        types::Value::Byte(vv) => *vv as i32,
        types::Value::Short(vv) => *vv as i32,
        types::Value::Int(vv) => *vv as i32,
        _ => 0,
    }
}

pub fn get_str(v: &types::Value) -> String {
    match v {
        types::Value::Bytes(sn) => std::str::from_utf8(sn).unwrap_or_default().to_owned(),
        _ => "".to_string(),
    }
}

pub fn get_proto_version(proto_map: &HashMap<u8, types::Value>, tag: u8) -> i16 {
    if let Some(vv) = proto_map.get(&tag) {
        match vv {
            types::Value::Byte(v) => *v as i16,
            types::Value::Short(v) => *v,
            _ => IVersion::Unknown as i16,
        }
    } else {
        IVersion::Unknown as i16
    }
}

pub fn get_proto_package_type(proto_map: &HashMap<u8, types::Value>, tag: u8) -> i8 {
    if let Some(pv) = proto_map.get(&tag) {
        match pv {
            types::Value::Byte(pt) => *pt,
            _ => CPackageType::Normal as i8,
        }
    } else {
        CPackageType::Normal as i8
    }
}

pub fn get_proto_request_id(proto_map: &HashMap<u8, types::Value>, tag: u8) -> u32 {
    if let Some(rv) = proto_map.get(&tag) {
        get_i32(rv) as u32
    } else {
        return 0;
    }
}

pub fn get_proto_ret(proto_map: &HashMap<u8, types::Value>) -> i32 {
    if let Some(rv) = proto_map.get(&TAG_RESP_RET) {
        get_i32(rv)
    } else {
        return 0;
    }
}

pub fn get_proto_string(proto_map: &HashMap<u8, types::Value>, tag: u8) -> String {
    if let Some(v) = proto_map.get(&tag) {
        get_str(v)
    } else {
        "".to_string()
    }
}

#[derive(Debug)]
pub struct JceBuf<'a> {
    pub buf: &'a [u8],
    skip_tag_set: HashSet<u8>,
}

impl<'a> JceBuf<'a> {
    // 使用字节数组初始化 JceBuf
    pub fn new(buf: &'a [u8], skip_tags: &[u8]) -> Self {
        let skip_tag_set = HashSet::from_iter(skip_tags.iter().cloned());
        JceBuf { buf, skip_tag_set }
    }

    pub fn read_to_hashmap(&mut self) -> HashMap<u8, types::Value> {
        let mut map = HashMap::new();
        while self.remaining() > 0 {
            let Ok(header) = self.read_header() else { break };
            if self.skip_tag_set.contains(&header.tag()) {
                let Ok(()) = self.skip_value(header.value_type()) else { break };
                continue;
            }
            let Ok(value) = self.read_value(header.value_type()) else { break };
            map.insert(header.tag(), value);
        }
        map
    }

    fn read_header(&mut self) -> Result<types::JceHeader> {
        let head = self.get_u8()?;
        // 取低四位
        let val_type = head & 0xF;
        // 取高四位
        let mut tag = head >> 4;

        if tag == 0xF {
            tag = self.get_u8()?;
        }
        Ok(types::JceHeader { val_type, tag })
    }

    fn read_type(&mut self) -> Result<u8> {
        Ok(self.get_u8()? & 0xF)
    }

    fn read_elem(&mut self) -> Result<types::Value> {
        let t = self.read_type()?;
        self.read_value(t)
    }

    fn read_len(&mut self) -> Result<usize> {
        let t = self.get_u8()?;
        let len = match t {
            types::BYTE => self.get_u8()? as usize,
            types::SHORT => self.get_u16()? as usize,
            types::INT => self.get_u32()? as usize,
            types::LONG => self.get_u64()? as usize,
            types::EMPTY => 0usize,
            _ => return Err(DecodeError),
        };
        Ok(len)
    }

    fn skip_elem(&mut self) -> Result<()> {
        let t = self.read_type()?;
        self.skip_value(t)
    }

    fn skip_value(&mut self, t: u8) -> Result<()> {
        match t {
            types::BYTE => self.validate_advance(1)?,
            types::SHORT => self.validate_advance(2)?,
            types::INT | types::FLOAT => self.validate_advance(4)?,
            types::DOUBLE | types::LONG => self.validate_advance(8)?,
            types::SHORT_BYTES => {
                let len = self.get_u8()? as usize;
                self.validate_advance(len)?;
            }
            types::LONG_BYTES => {
                let len = self.get_u32()? as usize;
                self.validate_advance(len)?;
            }
            types::STRUCT_START => {
                self.skip_elem()?;
            }
            types::STRUCT_END | types::EMPTY => {}
            types::MAP => {
                let len = self.read_len()?;
                for _ in 0..len * 2 {
                    self.skip_elem()?;
                }
            }
            types::LIST => {
                let len = self.read_len()?;
                for _ in 0..len {
                    self.skip_elem()?;
                }
            }
            types::SINGLE_LIST => {
                let tt = self.read_type()?;
                let len = self.read_len()?;
                let width = types::get_type_width(tt);
                self.validate_advance(len * width)?;
            }
            _ => return Err(DecodeError),
        }
        Ok(())
    }

    fn read_value(&mut self, t: u8) -> Result<types::Value> {
        let val = match t {
            types::BYTE => types::Value::Byte(self.get_i8()?),
            types::SHORT => types::Value::Short(self.get_i16()?),
            types::INT => types::Value::Int(self.get_i32()?),
            types::LONG => types::Value::Long(self.get_i64()?),
            types::FLOAT => types::Value::Float(self.get_f32()?),
            types::DOUBLE => types::Value::Double(self.get_f64()?),
            types::SHORT_BYTES => {
                let len = self.get_u8()? as usize;
                types::Value::Bytes(self.vec_from_buf(len)?)
            }
            types::LONG_BYTES => types::Value::Bytes({
                let len = self.get_i32()? as usize;
                self.check(len)?;
                self.vec_from_buf(len)?
            }),
            types::MAP => types::Value::Map({
                let len = self.read_len()?;
                let mut map = HashMap::new();
                for _ in 0..len {
                    let key = self.read_elem()?;
                    let value = self.read_elem()?;
                    let s = if let types::Value::Bytes(b) = key {
                        let str = std::str::from_utf8(b.as_slice()).unwrap_or_default();
                        str.to_owned()
                    } else {
                        return Err(DecodeError);
                    };
                    map.insert(s, value);
                }
                map
            }),
            types::LIST => types::Value::List({
                let len = self.read_len()?;
                let mut list = Vec::with_capacity(len);
                for _ in 0..len {
                    list.push(self.read_elem()?);
                }
                list
            }),
            types::SINGLE_LIST => types::Value::Bytes({
                let tt = self.read_type()?;
                let len = self.read_len()?;
                let width = types::get_type_width(tt);
                self.vec_from_buf(len * width)?
            }),
            types::EMPTY => types::Value::Empty,
            _ => return Err(DecodeError),
        };
        Ok(val)
    }

    fn check(&mut self, cnt: usize) -> Result<()> {
        if self.remaining() < cnt {
            Err(DecodeError)
        } else {
            Ok(())
        }
    }

    fn vec_from_buf(&mut self, n: usize) -> Result<Vec<u8>> {
        self.check(n)?;
        if n > 0 {
            let b = self.buf[..n].to_vec();
            self.advance(n);
            Ok(b)
        } else {
            Ok(Vec::new())
        }
    }

    fn readn(&mut self, n: usize) -> Result<&[u8]> {
        self.check(n)?;
        let ret = &self.buf[..n];
        self.advance(n);
        Ok(ret)
    }

    fn remaining(&self) -> usize {
        return self.buf.len();
    }

    fn advance(&mut self, n: usize) {
        self.buf = &self.buf[n..];
    }

    fn validate_advance(&mut self, n: usize) -> Result<()> {
        self.check(n)?;
        self.buf = &self.buf[n..];
        Ok(())
    }

    fn get_u8(&mut self) -> Result<u8> {
        Ok(self.readn(1)?[0] as u8)
    }

    fn get_u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.readn(2)?.try_into().unwrap()))
    }

    fn get_u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.readn(4)?.try_into().unwrap()))
    }

    fn get_u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.readn(4)?.try_into().unwrap()))
    }

    fn get_i8(&mut self) -> Result<i8> {
        Ok(self.readn(1)?[0] as i8)
    }

    fn get_i16(&mut self) -> Result<i16> {
        Ok(i16::from_be_bytes(self.readn(2)?.try_into().unwrap()))
    }

    fn get_i32(&mut self) -> Result<i32> {
        Ok(i32::from_be_bytes(self.readn(4)?.try_into().unwrap()))
    }

    fn get_i64(&mut self) -> Result<i64> {
        Ok(i64::from_be_bytes(self.readn(8)?.try_into().unwrap()))
    }

    fn get_f32(&mut self) -> Result<f32> {
        Ok(f32::from_be_bytes(self.readn(4)?.try_into().unwrap()))
    }

    fn get_f64(&mut self) -> Result<f64> {
        Ok(f64::from_be_bytes(self.readn(8)?.try_into().unwrap()))
    }
}
