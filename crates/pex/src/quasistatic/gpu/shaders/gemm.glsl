#version 460
layout(local_size_x = 256) in;
layout(set = 0, binding = 0) readonly buffer A { float a[]; };
layout(set = 0, binding = 1) readonly buffer B { float b[]; };
layout(set = 0, binding = 2) buffer C { float c[]; };
layout(push_constant) uniform Params { uint m; uint k_dim; uint n; };
void main() {
    uint idx = gl_GlobalInvocationID.x;
    if (idx >= m * n) return;
    uint i = idx / n;
    uint j = idx % n;
    float acc = 0.0;
    uint arow = i * k_dim;
    for (uint p = 0; p < k_dim; p++) {
        acc += a[arow + p] * b[p * n + j];
    }
    c[idx] = acc;
}
