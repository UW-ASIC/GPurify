#version 460
layout(local_size_x = 256) in;
layout(set = 0, binding = 0) readonly buffer Inv { float inv[]; };
layout(set = 0, binding = 1) readonly buffer R { float r[]; };
layout(set = 0, binding = 2) buffer Out { float out_buf[]; };
layout(push_constant) uniform Params { uint nblocks; uint block_size; };
void main() {
    uint blk = gl_GlobalInvocationID.x;
    if (blk >= nblocks) return;
    uint base = blk * block_size;
    uint inv_base = blk * block_size * block_size;
    for (uint i = 0; i < block_size; i++) {
        float acc = 0.0;
        for (uint j = 0; j < block_size; j++) {
            acc += inv[inv_base + i * block_size + j] * r[base + j];
        }
        out_buf[base + i] = acc;
    }
}
