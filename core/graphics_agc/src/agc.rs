//! AGC (Autonomous Graphics Engine) context and pipeline abstraction.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrimitiveTopology {
    PointList,
    LineList,
    LineStrip,
    TriangleList,
    TriangleStrip,
    PatchList,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SurfaceFormat {
    R8G8B8A8Unorm,
    B8G8R8A8Unorm,
    R16G16B16A16Float,
    R32G32B32A32Float,
    D32Float,
    D24UnormS8Uint,
}

#[derive(Debug, Clone)]
pub struct ViewportScissor {
    pub x: f32,
    pub y: f32,
    pub width: f32,
    pub height: f32,
    pub min_depth: f32,
    pub max_depth: f32,
}

#[derive(Debug, Clone)]
pub struct RenderTargetDesc {
    pub format: SurfaceFormat,
    pub base_gpa: u64,
    pub width: u32,
    pub height: u32,
    pub pitch: u32,
}

#[derive(Debug, Clone, Default)]
pub struct AgcDrawState {
    pub primitive_topology: Option<PrimitiveTopology>,
    pub viewport: Option<ViewportScissor>,
    pub render_targets: Vec<RenderTargetDesc>,
    pub depth_target: Option<RenderTargetDesc>,
    pub vertex_buffer_base: u64,
    pub index_buffer_base: u64,
}
