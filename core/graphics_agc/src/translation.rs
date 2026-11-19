//! Translation layer stubs for converting decoded AGC/PM4 commands into Vulkan / NIR.

use crate::agc::AgcDrawState;
use crate::pm4::{Pm4Packet, IT_DRAW_INDEX_AUTO, IT_DISPATCH_DIRECT, IT_SET_CONTEXT_REG};

#[derive(Debug, PartialEq, Eq)]
pub enum VulkanCommandStub {
    BindPipeline { pipeline_id: u64 },
    SetViewport { width: f32, height: f32 },
    Draw { vertex_count: u32, instance_count: u32, first_vertex: u32 },
    DispatchCompute { group_count_x: u32, group_count_y: u32, group_count_z: u32 },
    PipelineBarrier,
}

pub struct AgcToVulkanTranslator {
    state: AgcDrawState,
}

impl Default for AgcToVulkanTranslator {
    fn default() -> Self {
        Self::new()
    }
}

impl AgcToVulkanTranslator {
    pub fn new() -> Self {
        Self {
            state: AgcDrawState::default(),
        }
    }

    /// Translate a sequence of decoded PM4 packets into host Vulkan command stubs.
    pub fn translate_packets(&mut self, packets: &[Pm4Packet]) -> Vec<VulkanCommandStub> {
        let mut vk_cmds = Vec::new();

        for packet in packets {
            match packet {
                Pm4Packet::Type3 { opcode, payload, .. } => {
                    match *opcode {
                        IT_DRAW_INDEX_AUTO => {
                            let count = payload.first().copied().unwrap_or(0);
                            vk_cmds.push(VulkanCommandStub::Draw {
                                vertex_count: count,
                                instance_count: 1,
                                first_vertex: 0,
                            });
                        }
                        IT_DISPATCH_DIRECT => {
                            let x = payload.get(0).copied().unwrap_or(1);
                            let y = payload.get(1).copied().unwrap_or(1);
                            let z = payload.get(2).copied().unwrap_or(1);
                            vk_cmds.push(VulkanCommandStub::DispatchCompute {
                                group_count_x: x,
                                group_count_y: y,
                                group_count_z: z,
                            });
                        }
                        IT_SET_CONTEXT_REG => {
                            // Context register updates (viewport, render target formats, etc.)
                        }
                        _ => {}
                    }
                }
                _ => {}
            }
        }

        vk_cmds
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_translate_draw_auto() {
        let mut translator = AgcToVulkanTranslator::new();
        let packet = Pm4Packet::Type3 {
            opcode: IT_DRAW_INDEX_AUTO,
            predicate: false,
            payload: vec![36], // 36 vertices (cube)
        };
        let cmds = translator.translate_packets(&[packet]);
        assert_eq!(cmds.len(), 1);
        assert_eq!(
            cmds[0],
            VulkanCommandStub::Draw {
                vertex_count: 36,
                instance_count: 1,
                first_vertex: 0,
            }
        );
    }
}
