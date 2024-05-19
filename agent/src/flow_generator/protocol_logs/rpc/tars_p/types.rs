use std::collections::HashMap;
use std::hash::{Hash, Hasher};

// 长度：1 字节，类型：i8
pub const BYTE: u8 = 0;
// 长度：2 字节，类型：i16
pub const SHORT: u8 = 1;
// 长度：4 字节，类型：i32
pub const INT: u8 = 2;
// 长度：8 字节，类型：i64
pub const LONG: u8 = 3;
// 长度：4 字节，类型：f32
pub const FLOAT: u8 = 4;
// 长度：8 字节，类型：f64
pub const DOUBLE: u8 = 5;
// Length(1 bytes) | Value(*)
pub const SHORT_BYTES: u8 = 6;
// Length(4 bytes) | Value(*)
pub const LONG_BYTES: u8 = 7;
// Length(Elem) | []<Key(Elem), Value(Elem)>
pub const MAP: u8 = 8;
// Length(Elem) | []Elem
pub const LIST: u8 = 9;
// 忽略，外层通信协议不涉及嵌套
pub const STRUCT_START: u8 = 10;
pub const STRUCT_END: u8 = 11;
// 表示数字 0
pub const EMPTY: u8 = 12;
// Type(目前仅支持 BYTE) | Length(Elem) | Elem(BYTE)
pub const SINGLE_LIST: u8 = 13;


#[derive(Debug)]
#[allow(dead_code)]
pub enum Value {
    Byte(i8),
    Short(i16),
    Int(i32),
    Long(i64),
    Float(f32),
    Double(f64),
    Bytes(Vec<u8>),
    Struct(HashMap<u8, Value>),
    Map(HashMap<String, Value>),
    List(Vec<Value>),
    Empty,
}


impl PartialEq for Value {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Value::Byte(a), Value::Byte(b)) => a == b,
            (Value::Short(a), Value::Short(b)) => a == b,
            (Value::Int(a), Value::Int(b)) => a == b,
            (Value::Long(a), Value::Long(b)) => a == b,
            (Value::Float(a), Value::Float(b)) => a == b,
            (Value::Double(a), Value::Double(b)) => a == b,
            (Value::Bytes(a), Value::Bytes(b)) => a == b,
            (Value::Struct(a), Value::Struct(b)) => a == b,
            (Value::Map(a), Value::Map(b)) => a == b,
            (Value::List(a), Value::List(b)) => a == b,
            (Value::Empty, Value::Empty) => true,
            _ => false,
        }
    }
}

impl Eq for Value {}

impl Hash for Value {
    fn hash<H: Hasher>(&self, state: &mut H) {
        match self {
            Value::Byte(b) => b.hash(state),
            Value::Short(s) => s.hash(state),
            Value::Int(i) => i.hash(state),
            Value::Long(l) => l.hash(state),
            Value::Float(f) => {
                state.write_u8(b'f');
                state.write_u32(f.to_bits());
            }
            Value::Double(d) => {
                state.write_u8(b'd');
                state.write_u64(d.to_bits());
            }
            Value::Bytes(b) => b.hash(state),
            Value::Struct(s) => {
                state.write_usize(s.len());
                state.write_u8(b's');

                for (k, v) in s.iter() {
                    state.write_u8(*k);
                    v.hash(state);
                }
            }
            Value::Map(m) => {
                state.write_usize(m.len());
                state.write_u8(b'm');

                for (k, v) in m.iter() {
                    k.hash(state);
                    v.hash(state);
                }
            }
            Value::List(v) => {
                for val in v {
                    val.hash(state);
                }
            }
            Value::Empty => state.write(b"empty"),
        }
    }
}


#[derive(Debug)]
pub struct JceHeader {
    pub(crate) val_type: u8,
    pub(crate) tag: u8,
}

impl JceHeader {
    #[inline]
    pub fn value_type(&self) -> u8 {
        self.val_type
    }

    #[inline]
    pub fn tag(&self) -> u8 {
        self.tag
    }
}

pub fn get_type_width(t: u8) -> usize {
    match t {
        BYTE => 1,
        SHORT => 2,
        INT | FLOAT => 4,
        LONG | DOUBLE => 8,
        _ => 1,
    }
}