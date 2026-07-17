#version 460
layout(local_size_x = 256) in;
layout(set = 0, binding = 0) readonly buffer Tx { float tx[]; };
layout(set = 0, binding = 1) readonly buffer Ty { float ty[]; };
layout(set = 0, binding = 2) readonly buffer Tz { float tz[]; };
layout(set = 0, binding = 3) readonly buffer Sx { float sx[]; };
layout(set = 0, binding = 4) readonly buffer Sy { float sy[]; };
layout(set = 0, binding = 5) readonly buffer Sz { float sz[]; };
layout(set = 0, binding = 6) readonly buffer Sq { float sq[]; };
layout(set = 0, binding = 7) buffer Phi { float phi[]; };
layout(push_constant) uniform Params { uint n_targets; uint n_sources; };
void main() {
    uint i = gl_GlobalInvocationID.x;
    if (i >= n_targets) return;
    float xi = tx[i], yi = ty[i], zi = tz[i];
    float acc = 0.0;
    for (uint j = 0; j < n_sources; j++) {
        float dx = xi - sx[j], dy = yi - sy[j], dz = zi - sz[j];
        float r2 = dx*dx + dy*dy + dz*dz;
        if (r2 > 0.0) acc += sq[j] * inversesqrt(r2);
    }
    phi[i] = acc;
}
