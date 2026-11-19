//! PM4 (Packet Micro-Engine 4) command buffer packet definitions and decoder.
//!
//! Models the hardware command submission format processed by the AMD RDNA 2 GPU.

pub const PM4_TYPE_0: u32 = 0;
pub const PM4_TYPE_2: u32 = 2;
pub const PM4_TYPE_3: u32 = 3;

// Common AMD / RDNA 2 Type-3 PM4 opcodes
pub const IT_NOP: u32 = 0x10;
pub const IT_SET_BASE: u32 = 0x11;
pub const IT_INDEX_BUFFER_SIZE: u32 = 0x13;
pub const IT_DISPATCH_DIRECT: u32 = 0x15;
pub const IT_DISPATCH_INDIRECT: u32 = 0x16;
pub const IT_DRAW_INDEX_2: u32 = 0x27;
pub const IT_INDEX_TYPE: u32 = 0x2A;
pub const IT_DRAW_INDEX_AUTO: u32 = 0x2D;
pub const IT_WAIT_REG_MEM: u32 = 0x3C;
pub const IT_EVENT_WRITE: u32 = 0x46;
pub const IT_ACQUIRE_MEM: u32 = 0x58;
pub const IT_RELEASE_MEM: u32 = 0x59;
pub const IT_SET_CONTEXT_REG: u32 = 0x69;
pub const IT_SET_SH_REG: u32 = 0x76;
pub const IT_SET_UCONFIG_REG: u32 = 0x79;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pm4Packet {
    Type0 {
        base_index: u32,
        count: u32,
        values: Vec<u32>,
    },
    Type2Nop,
    Type3 {
        opcode: u32,
        predicate: bool,
        payload: Vec<u32>,
    },
    UnknownHeader(u32),
}

#[derive(Debug, Default)]
pub struct Pm4Decoder;

impl Pm4Decoder {
    pub fn new() -> Self {
        Self
    }

    /// Decode a linear stream of DWORDs (32-bit words) into PM4 packets.
    pub fn decode_stream(&self, dwords: &[u32]) -> Vec<Pm4Packet> {
        let mut packets = Vec::new();
        let mut idx = 0;

        while idx < dwords.len() {
            let header = dwords[idx];
            let packet_type = (header >> 30) & 0x3;

            match packet_type {
                PM4_TYPE_0 => {
                    let base_index = header & 0xFFFF;
                    let count = ((header >> 16) & 0x3FFF) + 1;
                    idx += 1;
                    let end = (idx + count as usize).min(dwords.len());
                    let values = dwords[idx..end].to_vec();
                    idx = end;
                    packets.push(Pm4Packet::Type0 {
                        base_index,
                        count,
                        values,
                    });
                }
                PM4_TYPE_2 => {
                    idx += 1;
                    packets.push(Pm4Packet::Type2Nop);
                }
                PM4_TYPE_3 => {
                    let opcode = (header >> 8) & 0xFF;
                    let count = ((header >> 16) & 0x3FFF) + 1;
                    let predicate = (header & 0x1) != 0;
                    idx += 1;
                    let end = (idx + count as usize).min(dwords.len());
                    let payload = dwords[idx..end].to_vec();
                    idx = end;
                    packets.push(Pm4Packet::Type3 {
                        opcode,
                        predicate,
                        payload,
                    });
                }
                _ => {
                    packets.push(Pm4Packet::UnknownHeader(header));
                    idx += 1;
                }
            }
        }

        packets
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_type3_set_context_reg() {
        let decoder = Pm4Decoder::new();
        // Type-3 packet header: type=3 (bit 30..31), count=2 (count-1=1 in bits 16..29), opcode=IT_SET_CONTEXT_REG (0x69 in bits 8..15)
        let header = (3 << 30) | (1 << 16) | (IT_SET_CONTEXT_REG << 8);
        let stream = vec![header, 0x00000200, 0xDEADBEEF];

        let packets = decoder.decode_stream(&stream);
        assert_eq!(packets.len(), 1);
        match &packets[0] {
            Pm4Packet::Type3 { opcode, payload, .. } => {
                assert_eq!(*opcode, IT_SET_CONTEXT_REG);
                assert_eq!(payload.len(), 2);
                assert_eq!(payload[0], 0x00000200);
                assert_eq!(payload[1], 0xDEADBEEF);
            }
            _ => panic!("Expected Type-3 PM4 packet"),
        }
    }
}
