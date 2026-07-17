//! `#[verify_kernel]`: one scalar rule function, compiled at build time into
//! a CPU version and a GPU version.
//!
//! The annotated function is the single source of truth for the rule's
//! per-element math. The macro emits:
//!
//! * the function itself, kept callable from plain Rust (the CPU version);
//!   with the `gpu` cargo feature it is additionally annotated `#[cubecl::cube]`
//!   so the *same body* compiles to GPU IR;
//! * `<name>_kernel::cpu(...)` — a plain (rayon-free, allocation-light) slice
//!   driver looping the function;
//! * `<name>_kernel::gpu(...)` — a CubeCL launcher for the generated device
//!   kernel wrapping the same function (`None` without the feature/device);
//! * `<name>_kernel::run(backend, ...)` — implicit dispatch: try GPU when
//!   asked, always fall back to the CPU version.
//!
//! Shapes (`shape = ...`):
//! * `map` — `out[i] = f(col1[i], .., #[uniform] s..)`
//! * `min_over` — `out[i] = min over j of f(q..[i], #[target] t..[j], s..)`
//! * `pair` — `out[i] = f(col..[pa[i]], col..[pb[i]], s..)` (gather; the
//!   function's column params must come in two equal halves, a-side then b-side)
//! * `cross_pairs` — per descriptor `(a0,a1,b0,b1)`: flag 1 iff any
//!   `(a in a0..a1, b in b0..b1)` has `f(col..[a], col..[b], s..) != 0`
//! * `cross_self` — per descriptor `(s,e)`: flag 1 iff any `s <= u < v < e`
//!   has `f(col..[u], col..[v], s..) != 0`
//! * `segmented_min` — CSR gather-reduce:
//!   `out[i] = min over k in seg_start[i]..seg_start[i+1] of f(col..[idx[k]], s..)`;
//!   empty segments yield `MAX`. `idx`/`seg_start` ride as two implicit u32
//!   columns after the value columns (`seg_start.len() == out.len() + 1`).
//!
//! `#[kernel_fn]` marks a helper callable from kernels and plain Rust alike.

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::{format_ident, quote};
use syn::{parse_macro_input, FnArg, Ident, ItemFn, Pat, Type};

/// Helper usable from both compilations: plain Rust always, cube dialect
/// under the `gpu` feature.
#[proc_macro_attribute]
pub fn kernel_fn(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let func = parse_macro_input!(item as ItemFn);
    quote! {
        #[cfg_attr(feature = "gpu", cubecl::cube)]
        #func
    }
    .into()
}

struct Shape {
    kind: ShapeKind,
}

#[derive(PartialEq, Clone, Copy)]
enum ShapeKind {
    Map,
    MinOver,
    Pair,
    CrossPairs,
    CrossSelf,
    SegmentedMin,
}

struct Param {
    name: Ident,
    ty: Type,
    uniform: bool,
    target: bool,
}

fn parse_params(func: &ItemFn) -> syn::Result<Vec<Param>> {
    let mut out = Vec::new();
    for arg in &func.sig.inputs {
        let FnArg::Typed(pt) = arg else {
            return Err(syn::Error::new_spanned(arg, "self params are unsupported"));
        };
        let Pat::Ident(pi) = &*pt.pat else {
            return Err(syn::Error::new_spanned(
                pt,
                "pattern params are unsupported",
            ));
        };
        let uniform = pt.attrs.iter().any(|a| a.path().is_ident("uniform"));
        let target = pt.attrs.iter().any(|a| a.path().is_ident("target"));
        out.push(Param {
            name: pi.ident.clone(),
            ty: (*pt.ty).clone(),
            uniform,
            target,
        });
    }
    Ok(out)
}

/// Strip `#[uniform]` / `#[target]` param markers so the emitted fn is plain Rust.
fn strip_param_attrs(func: &mut ItemFn) {
    for arg in func.sig.inputs.iter_mut() {
        if let FnArg::Typed(pt) = arg {
            pt.attrs
                .retain(|a| !a.path().is_ident("uniform") && !a.path().is_ident("target"));
        }
    }
}

#[proc_macro_attribute]
pub fn verify_kernel(attr: TokenStream, item: TokenStream) -> TokenStream {
    let mut func = parse_macro_input!(item as ItemFn);
    let mut shape: Option<Shape> = None;

    let parser = syn::meta::parser(|meta| {
        if meta.path.is_ident("shape") {
            let value: Ident = meta.value()?.parse()?;
            let kind = match value.to_string().as_str() {
                "map" => ShapeKind::Map,
                "min_over" => ShapeKind::MinOver,
                "pair" => ShapeKind::Pair,
                "cross_pairs" => ShapeKind::CrossPairs,
                "cross_self" => ShapeKind::CrossSelf,
                "segmented_min" => ShapeKind::SegmentedMin,
                other => {
                    return Err(meta.error(format!("unknown shape `{other}`")));
                }
            };
            shape = Some(Shape { kind });
            Ok(())
        } else {
            Err(meta.error("expected `shape = ...`"))
        }
    });
    parse_macro_input!(attr with parser);
    let Some(shape) = shape else {
        return syn::Error::new_spanned(&func.sig, "missing `shape = ...`")
            .to_compile_error()
            .into();
    };

    let params = match parse_params(&func) {
        Ok(p) => p,
        Err(e) => return e.to_compile_error().into(),
    };
    strip_param_attrs(&mut func);

    let out_ty: Type = match &func.sig.output {
        syn::ReturnType::Type(_, t) => (**t).clone(),
        syn::ReturnType::Default => {
            return syn::Error::new_spanned(&func.sig, "kernel must return a value")
                .to_compile_error()
                .into();
        }
    };

    let cols: Vec<&Param> = params.iter().filter(|p| !p.uniform && !p.target).collect();
    let targets: Vec<&Param> = params.iter().filter(|p| p.target).collect();
    let uniforms: Vec<&Param> = params.iter().filter(|p| p.uniform).collect();

    if shape.kind != ShapeKind::MinOver && !targets.is_empty() {
        return syn::Error::new_spanned(
            &func.sig,
            "#[target] params are only valid with shape = min_over",
        )
        .to_compile_error()
        .into();
    }
    let halves_needed = matches!(
        shape.kind,
        ShapeKind::Pair | ShapeKind::CrossPairs | ShapeKind::CrossSelf
    );
    if halves_needed && cols.len() % 2 != 0 {
        return syn::Error::new_spanned(
            &func.sig,
            "pair/cross shapes need an even number of column params (a-side then b-side)",
        )
        .to_compile_error()
        .into();
    }

    let name = func.sig.ident.clone();
    let vis = func.vis.clone();
    let mod_name = format_ident!("{}_kernel", name);

    let body = match shape.kind {
        ShapeKind::Map => gen_map(&name, &cols, &uniforms, &out_ty),
        ShapeKind::MinOver => gen_min_over(&name, &cols, &targets, &uniforms, &out_ty),
        ShapeKind::Pair => gen_pair(&name, &cols, &uniforms, &out_ty),
        ShapeKind::CrossPairs => gen_cross(&name, &cols, &uniforms, &out_ty, false),
        ShapeKind::CrossSelf => gen_cross(&name, &cols, &uniforms, &out_ty, true),
        ShapeKind::SegmentedMin => gen_segmented_min(&name, &cols, &uniforms, &out_ty),
    };

    quote! {
        #[cfg_attr(feature = "gpu", cubecl::cube)]
        #func

        #[allow(clippy::too_many_arguments)]
        #vis mod #mod_name {
            use super::*;
            #body
        }
    }
    .into()
}

fn names(ps: &[&Param]) -> Vec<Ident> {
    ps.iter().map(|p| p.name.clone()).collect()
}
fn types(ps: &[&Param]) -> Vec<Type> {
    ps.iter().map(|p| p.ty.clone()).collect()
}

/// `run(backend, ...)` dispatcher shared by all shapes.
fn gen_run(sig_args: &TokenStream2, call_args: &TokenStream2, out_ty: &Type) -> TokenStream2 {
    quote! {
        /// One rule function, two compilations: GPU when asked and usable,
        /// the very same code on CPU otherwise.
        pub fn run(backend: crate::backend::Backend, #sig_args) -> Vec<#out_ty> {
            if matches!(backend, crate::backend::Backend::Gpu) {
                if let Some(v) = gpu(#call_args) {
                    return v;
                }
            }
            cpu(#call_args)
        }
    }
}

fn gpu_stub(sig_args: &TokenStream2, call_args: &TokenStream2, out_ty: &Type) -> TokenStream2 {
    quote! {
        /// GPU compilation of the same function. `None` => caller uses `cpu`.
        pub fn gpu(#sig_args) -> Option<Vec<#out_ty>> {
            #[cfg(feature = "gpu")]
            {
                return gpu_impl::launch(#call_args);
            }
            #[cfg(not(feature = "gpu"))]
            {
                let _ = (#call_args);
                None
            }
        }
    }
}

/// Session support: typed column reads + uniform reads + output serialization
/// for the generated `cpu_fn`, shared by every shape.
fn session_cpu_prelude(
    cols_n: &[Ident],
    cols_t: &[Type],
    un: &[Ident],
    ut: &[Type],
) -> TokenStream2 {
    let col_reads = cols_n.iter().zip(cols_t).enumerate().map(|(i, (n, t))| {
        quote! { let #n: Vec<#t> = store.read_vec::<#t>(cols[#i]); }
    });
    let uni_reads = un.iter().zip(ut).enumerate().map(|(i, (n, t))| {
        quote! { let #n: #t = uniforms.get::<#t>(#i); }
    });
    quote! {
        #(#col_reads)*
        #(#uni_reads)*
    }
}

fn session_serialize(out_ty: &Type) -> TokenStream2 {
    quote! {
        {
            use crate::session::SessionElem;
            let mut bytes = Vec::with_capacity(values.len() * <#out_ty as SessionElem>::SIZE);
            for v in values {
                v.write_to(&mut bytes);
            }
            bytes
        }
    }
}

fn gen_map(name: &Ident, cols: &[&Param], uniforms: &[&Param], out_ty: &Type) -> TokenStream2 {
    let cn = names(cols);
    let ct = types(cols);
    let un = names(uniforms);
    let ut = types(uniforms);
    let first = cn[0].clone();

    let sig_args = quote! { #(#cn: &[#ct],)* #(#un: #ut),* };
    let call_args = quote! { #(#cn,)* #(#un),* };

    let run = gen_run(&sig_args, &call_args, out_ty);
    let gpu = gpu_stub(&sig_args, &call_args, out_ty);

    let prelude = session_cpu_prelude(&cn, &ct, &un, &ut);
    let serialize = session_serialize(out_ty);
    let in_count = cn.len();
    let ins_args = (0..in_count).map(|i| {
        quote! { ArrayArg::from_raw_parts(ins[#i].0.clone(), ins[#i].1), }
    });
    let uni_args = ut.iter().enumerate().map(|(i, t)| {
        quote! { uniforms.get::<#t>(#i), }
    });
    let bind = quote! {
        /// Session binding: same kernel over device-resident columns.
        pub fn bind(
            #(#cn: &crate::session::Col<#ct>,)* #(#un: #ut),*
        ) -> crate::session::BoundKernel {
            crate::session::BoundKernel {
                cols: vec![#(#cn.erased()),*],
                uniforms: crate::session::Uniforms::new()#(.push(#un))*,
                host: Vec::new(),
                out_len: #first.len(),
                out_elem_size: core::mem::size_of::<#out_ty>(),
                cpu_fn: session_cpu,
                #[cfg(feature = "gpu")]
                gpu_fn: gpu_impl::enqueue,
            }
        }

        fn session_cpu(
            store: &crate::session::CpuStore,
            cols: &[crate::session::ColRef],
            uniforms: &crate::session::Uniforms,
            _host: &[u8],
            _out_len: usize,
        ) -> Vec<u8> {
            #prelude
            let values = cpu(#(&#cn,)* #(#un),*);
            #serialize
        }
    };
    let session_gpu = quote! {
        /// Session enqueue: launch over already-resident handles; never syncs.
        pub fn enqueue(
            client: &'static crate::backend::cube::Client,
            ins: &[(cubecl::server::Handle, usize)],
            out: (cubecl::server::Handle, usize),
            uniforms: &crate::session::Uniforms,
            _host: &[u8],
        ) {
            let n = out.1;
            if n == 0 { return; }
            unsafe {
                device::launch_unchecked::<CudaRuntime>(
                    client,
                    CubeCount::Static((n as u32).div_ceil(CUBE_DIM), 1, 1),
                    CubeDim::new_1d(CUBE_DIM),
                    #(#ins_args)*
                    #(#uni_args)*
                    ArrayArg::from_raw_parts(out.0.clone(), n),
                );
            }
        }
    };

    quote! {
        /// CPU compilation of the same function.
        pub fn cpu(#sig_args) -> Vec<#out_ty> {
            (0..#first.len()).map(|i| super::#name(#(#cn[i],)* #(#un),*)).collect()
        }
        #gpu
        #run
        #bind

        #[cfg(feature = "gpu")]
        mod gpu_impl {
            use cubecl::prelude::*;
            use cubecl::cuda::CudaRuntime;
            use crate::backend::cube::{client, contain, upload, read_out, CUBE_DIM};

            #[cube(launch_unchecked)]
            fn device(#(#cn: &Array<#ct>,)* #(#un: #ut,)* out: &mut Array<#out_ty>) {
                if ABSOLUTE_POS < out.len() {
                    out[ABSOLUTE_POS] = super::super::#name(#(#cn[ABSOLUTE_POS],)* #(#un),*);
                }
            }

            #session_gpu

            pub fn launch(#(#cn: &[#ct],)* #(#un: #ut),*) -> Option<Vec<#out_ty>> {
                let client = client()?;
                let n = #first.len();
                if n == 0 { return Some(Vec::new()); }
                contain(|| {
                    #(let #cn = upload(client, #cn);)*
                    let out = client.empty(n * core::mem::size_of::<#out_ty>());
                    unsafe {
                        device::launch_unchecked::<CudaRuntime>(
                            client,
                            CubeCount::Static((n as u32).div_ceil(CUBE_DIM), 1, 1),
                            CubeDim::new_1d(CUBE_DIM),
                            #(ArrayArg::from_raw_parts(#cn, n),)*
                            #(#un,)*
                            ArrayArg::from_raw_parts(out.clone(), n),
                        );
                    }
                    read_out::<#out_ty>(client, out, n)
                })
            }
        }
    }
}

fn gen_min_over(
    name: &Ident,
    cols: &[&Param],
    targets: &[&Param],
    uniforms: &[&Param],
    out_ty: &Type,
) -> TokenStream2 {
    let qn = names(cols);
    let qt = types(cols);
    let tn = names(targets);
    let tt = types(targets);
    let un = names(uniforms);
    let ut = types(uniforms);
    let first_q = qn[0].clone();
    let first_t = tn[0].clone();

    let sig_args = quote! { #(#qn: &[#qt],)* #(#tn: &[#tt],)* #(#un: #ut),* };
    let call_args = quote! { #(#qn,)* #(#tn,)* #(#un),* };

    let run = gen_run(&sig_args, &call_args, out_ty);
    let gpu = gpu_stub(&sig_args, &call_args, out_ty);

    let all_n: Vec<Ident> = qn.iter().chain(&tn).cloned().collect();
    let all_t: Vec<Type> = qt.iter().chain(&tt).cloned().collect();
    let prelude = session_cpu_prelude(&all_n, &all_t, &un, &ut);
    let serialize = session_serialize(out_ty);
    let q_count = qn.len();
    let in_count = all_n.len();
    let ins_args = (0..in_count).map(|i| {
        quote! { ArrayArg::from_raw_parts(ins[#i].0.clone(), ins[#i].1), }
    });
    let uni_args = ut.iter().enumerate().map(|(i, t)| {
        quote! { uniforms.get::<#t>(#i), }
    });
    let bind = quote! {
        /// Session binding: same kernel over device-resident columns.
        pub fn bind(
            #(#qn: &crate::session::Col<#qt>,)* #(#tn: &crate::session::Col<#tt>,)*
            #(#un: #ut),*
        ) -> crate::session::BoundKernel {
            crate::session::BoundKernel {
                cols: vec![#(#all_n.erased()),*],
                uniforms: crate::session::Uniforms::new()#(.push(#un))*,
                host: Vec::new(),
                out_len: #first_q.len(),
                out_elem_size: core::mem::size_of::<#out_ty>(),
                cpu_fn: session_cpu,
                #[cfg(feature = "gpu")]
                gpu_fn: gpu_impl::enqueue,
            }
        }

        fn session_cpu(
            store: &crate::session::CpuStore,
            cols: &[crate::session::ColRef],
            uniforms: &crate::session::Uniforms,
            _host: &[u8],
            _out_len: usize,
        ) -> Vec<u8> {
            #prelude
            let values = cpu(#(&#all_n,)* #(#un),*);
            #serialize
        }
    };
    let session_gpu = quote! {
        /// Session enqueue: launch over already-resident handles; never syncs.
        pub fn enqueue(
            client: &'static crate::backend::cube::Client,
            ins: &[(cubecl::server::Handle, usize)],
            out: (cubecl::server::Handle, usize),
            uniforms: &crate::session::Uniforms,
            _host: &[u8],
        ) {
            let n = out.1;
            if n == 0 { return; }
            let m = ins[#q_count].1;
            unsafe {
                device::launch_unchecked::<CudaRuntime>(
                    client,
                    CubeCount::Static((n as u32).div_ceil(CUBE_DIM), 1, 1),
                    CubeDim::new_1d(CUBE_DIM),
                    #(#ins_args)*
                    m as u32,
                    <#out_ty>::MAX,
                    #(#uni_args)*
                    ArrayArg::from_raw_parts(out.0.clone(), n),
                );
            }
        }
    };

    quote! {
        /// CPU compilation of the same function.
        pub fn cpu(#sig_args) -> Vec<#out_ty> {
            (0..#first_q.len())
                .map(|i| {
                    let mut best = <#out_ty>::MAX;
                    for j in 0..#first_t.len() {
                        let v = super::#name(#(#qn[i],)* #(#tn[j],)* #(#un),*);
                        if v < best { best = v; }
                    }
                    best
                })
                .collect()
        }
        #gpu
        #run
        #bind

        #[cfg(feature = "gpu")]
        mod gpu_impl {
            use cubecl::prelude::*;
            use cubecl::cuda::CudaRuntime;
            use crate::backend::cube::{client, contain, upload, read_out, CUBE_DIM};

            #session_gpu

            #[cube(launch_unchecked)]
            fn device(
                #(#qn: &Array<#qt>,)* #(#tn: &Array<#tt>,)* n_targets: u32, init: #out_ty,
                #(#un: #ut,)* out: &mut Array<#out_ty>,
            ) {
                if ABSOLUTE_POS < out.len() {
                    let mut best = init;
                    for j in 0..n_targets {
                        let v = super::super::#name(
                            #(#qn[ABSOLUTE_POS],)* #(#tn[j as usize],)* #(#un),*
                        );
                        if v < best { best = v; }
                    }
                    out[ABSOLUTE_POS] = best;
                }
            }

            pub fn launch(#(#qn: &[#qt],)* #(#tn: &[#tt],)* #(#un: #ut),*) -> Option<Vec<#out_ty>> {
                let client = client()?;
                let n = #first_q.len();
                let m = #first_t.len();
                if n == 0 { return Some(Vec::new()); }
                if m == 0 { return Some(vec![<#out_ty>::MAX; n]); }
                contain(|| {
                    #(let #qn = upload(client, #qn);)*
                    #(let #tn = upload(client, #tn);)*
                    let out = client.empty(n * core::mem::size_of::<#out_ty>());
                    unsafe {
                        device::launch_unchecked::<CudaRuntime>(
                            client,
                            CubeCount::Static((n as u32).div_ceil(CUBE_DIM), 1, 1),
                            CubeDim::new_1d(CUBE_DIM),
                            #(ArrayArg::from_raw_parts(#qn, n),)*
                            #(ArrayArg::from_raw_parts(#tn, m),)*
                            m as u32,
                            <#out_ty>::MAX,
                            #(#un,)*
                            ArrayArg::from_raw_parts(out.clone(), n),
                        );
                    }
                    read_out::<#out_ty>(client, out, n)
                })
            }
        }
    }
}

fn gen_pair(name: &Ident, cols: &[&Param], uniforms: &[&Param], out_ty: &Type) -> TokenStream2 {
    let half = cols.len() / 2;
    // a-side and b-side params index the SAME shared columns; the shared
    // column slices take the a-side names.
    let a = &cols[..half];
    let an = names(a);
    let at = types(a);
    let un = names(uniforms);
    let ut = types(uniforms);
    let first = an[0].clone();

    let sig_args = quote! { #(#an: &[#at],)* pairs_a: &[u32], pairs_b: &[u32], #(#un: #ut),* };
    let call_args = quote! { #(#an,)* pairs_a, pairs_b, #(#un),* };

    let run = gen_run(&sig_args, &call_args, out_ty);
    let gpu = gpu_stub(&sig_args, &call_args, out_ty);

    let prelude = session_cpu_prelude(&an, &at, &un, &ut);
    let serialize = session_serialize(out_ty);
    let col_count = an.len();
    let pa_idx = col_count;
    let pb_idx = col_count + 1;
    let ins_args = (0..col_count).map(|i| {
        quote! { ArrayArg::from_raw_parts(ins[#i].0.clone(), ins[#i].1), }
    });
    let uni_args = ut.iter().enumerate().map(|(i, t)| {
        quote! { uniforms.get::<#t>(#i), }
    });
    let bind = quote! {
        /// Session binding: same kernel over device-resident columns.
        pub fn bind(
            #(#an: &crate::session::Col<#at>,)*
            pairs_a: &crate::session::Col<u32>, pairs_b: &crate::session::Col<u32>,
            #(#un: #ut),*
        ) -> crate::session::BoundKernel {
            crate::session::BoundKernel {
                cols: vec![#(#an.erased(),)* pairs_a.erased(), pairs_b.erased()],
                uniforms: crate::session::Uniforms::new()#(.push(#un))*,
                host: Vec::new(),
                out_len: pairs_a.len(),
                out_elem_size: core::mem::size_of::<#out_ty>(),
                cpu_fn: session_cpu,
                #[cfg(feature = "gpu")]
                gpu_fn: gpu_impl::enqueue,
            }
        }

        fn session_cpu(
            store: &crate::session::CpuStore,
            cols: &[crate::session::ColRef],
            uniforms: &crate::session::Uniforms,
            _host: &[u8],
            _out_len: usize,
        ) -> Vec<u8> {
            #prelude
            let pairs_a: Vec<u32> = store.read_vec::<u32>(cols[#pa_idx]);
            let pairs_b: Vec<u32> = store.read_vec::<u32>(cols[#pb_idx]);
            let values = cpu(#(&#an,)* &pairs_a, &pairs_b, #(#un),*);
            #serialize
        }
    };
    let session_gpu = quote! {
        /// Session enqueue: launch over already-resident handles; never syncs.
        pub fn enqueue(
            client: &'static crate::backend::cube::Client,
            ins: &[(cubecl::server::Handle, usize)],
            out: (cubecl::server::Handle, usize),
            uniforms: &crate::session::Uniforms,
            _host: &[u8],
        ) {
            let m = out.1;
            if m == 0 { return; }
            unsafe {
                device::launch_unchecked::<CudaRuntime>(
                    client,
                    CubeCount::Static((m as u32).div_ceil(CUBE_DIM), 1, 1),
                    CubeDim::new_1d(CUBE_DIM),
                    #(#ins_args)*
                    ArrayArg::from_raw_parts(ins[#pa_idx].0.clone(), ins[#pa_idx].1),
                    ArrayArg::from_raw_parts(ins[#pb_idx].0.clone(), ins[#pb_idx].1),
                    #(#uni_args)*
                    ArrayArg::from_raw_parts(out.0.clone(), m),
                );
            }
        }
    };

    quote! {
        /// CPU compilation of the same function.
        pub fn cpu(#sig_args) -> Vec<#out_ty> {
            (0..pairs_a.len())
                .map(|i| {
                    let a = pairs_a[i] as usize;
                    let b = pairs_b[i] as usize;
                    super::#name(#(#an[a],)* #(#an[b],)* #(#un),*)
                })
                .collect()
        }
        #gpu
        #run
        #bind

        #[cfg(feature = "gpu")]
        mod gpu_impl {
            use cubecl::prelude::*;
            use cubecl::cuda::CudaRuntime;
            use crate::backend::cube::{client, contain, upload, read_out, CUBE_DIM};

            #session_gpu

            #[cube(launch_unchecked)]
            fn device(
                #(#an: &Array<#at>,)* pairs_a: &Array<u32>, pairs_b: &Array<u32>,
                #(#un: #ut,)* out: &mut Array<#out_ty>,
            ) {
                if ABSOLUTE_POS < out.len() {
                    let a = pairs_a[ABSOLUTE_POS] as usize;
                    let b = pairs_b[ABSOLUTE_POS] as usize;
                    out[ABSOLUTE_POS] = super::super::#name(#(#an[a],)* #(#an[b],)* #(#un),*);
                }
            }

            pub fn launch(
                #(#an: &[#at],)* pairs_a: &[u32], pairs_b: &[u32], #(#un: #ut),*
            ) -> Option<Vec<#out_ty>> {
                let client = client()?;
                let m = pairs_a.len();
                if m == 0 { return Some(Vec::new()); }
                contain(|| {
                    let n = #first.len();
                    #(let #an = upload(client, #an);)*
                    let hpa = upload(client, pairs_a);
                    let hpb = upload(client, pairs_b);
                    let out = client.empty(m * core::mem::size_of::<#out_ty>());
                    unsafe {
                        device::launch_unchecked::<CudaRuntime>(
                            client,
                            CubeCount::Static((m as u32).div_ceil(CUBE_DIM), 1, 1),
                            CubeDim::new_1d(CUBE_DIM),
                            #(ArrayArg::from_raw_parts(#an, n),)*
                            ArrayArg::from_raw_parts(hpa, m),
                            ArrayArg::from_raw_parts(hpb, m),
                            #(#un,)*
                            ArrayArg::from_raw_parts(out.clone(), m),
                        );
                    }
                    read_out::<#out_ty>(client, out, m)
                })
            }
        }
    }
}

fn gen_segmented_min(
    name: &Ident,
    cols: &[&Param],
    uniforms: &[&Param],
    out_ty: &Type,
) -> TokenStream2 {
    let cn = names(cols);
    let ct = types(cols);
    let un = names(uniforms);
    let ut = types(uniforms);

    let sig_args = quote! { #(#cn: &[#ct],)* idx: &[u32], seg_start: &[u32], #(#un: #ut),* };
    let call_args = quote! { #(#cn,)* idx, seg_start, #(#un),* };

    let run = gen_run(&sig_args, &call_args, out_ty);
    let gpu = gpu_stub(&sig_args, &call_args, out_ty);

    let prelude = session_cpu_prelude(&cn, &ct, &un, &ut);
    let serialize = session_serialize(out_ty);
    let col_count = cn.len();
    let idx_i = col_count;
    let seg_i = col_count + 1;
    let ins_args = (0..col_count).map(|i| {
        quote! { ArrayArg::from_raw_parts(ins[#i].0.clone(), ins[#i].1), }
    });
    let uni_args = ut.iter().enumerate().map(|(i, t)| {
        quote! { uniforms.get::<#t>(#i), }
    });
    let bind = quote! {
        /// Session binding: same kernel over device-resident columns.
        /// `seg_start` has one more entry than the output.
        pub fn bind(
            #(#cn: &crate::session::Col<#ct>,)*
            idx: &crate::session::Col<u32>, seg_start: &crate::session::Col<u32>,
            #(#un: #ut),*
        ) -> crate::session::BoundKernel {
            crate::session::BoundKernel {
                cols: vec![#(#cn.erased(),)* idx.erased(), seg_start.erased()],
                uniforms: crate::session::Uniforms::new()#(.push(#un))*,
                host: Vec::new(),
                out_len: seg_start.len() - 1,
                out_elem_size: core::mem::size_of::<#out_ty>(),
                cpu_fn: session_cpu,
                #[cfg(feature = "gpu")]
                gpu_fn: gpu_impl::enqueue,
            }
        }

        fn session_cpu(
            store: &crate::session::CpuStore,
            cols: &[crate::session::ColRef],
            uniforms: &crate::session::Uniforms,
            _host: &[u8],
            _out_len: usize,
        ) -> Vec<u8> {
            #prelude
            let idx: Vec<u32> = store.read_vec::<u32>(cols[#idx_i]);
            let seg_start: Vec<u32> = store.read_vec::<u32>(cols[#seg_i]);
            let values = cpu(#(&#cn,)* &idx, &seg_start, #(#un),*);
            #serialize
        }
    };
    let session_gpu = quote! {
        /// Session enqueue: launch over already-resident handles; never syncs.
        pub fn enqueue(
            client: &'static crate::backend::cube::Client,
            ins: &[(cubecl::server::Handle, usize)],
            out: (cubecl::server::Handle, usize),
            uniforms: &crate::session::Uniforms,
            _host: &[u8],
        ) {
            let n = out.1;
            if n == 0 { return; }
            unsafe {
                device::launch_unchecked::<CudaRuntime>(
                    client,
                    CubeCount::Static((n as u32).div_ceil(CUBE_DIM), 1, 1),
                    CubeDim::new_1d(CUBE_DIM),
                    #(#ins_args)*
                    ArrayArg::from_raw_parts(ins[#idx_i].0.clone(), ins[#idx_i].1),
                    ArrayArg::from_raw_parts(ins[#seg_i].0.clone(), ins[#seg_i].1),
                    <#out_ty>::MAX,
                    #(#uni_args)*
                    ArrayArg::from_raw_parts(out.0.clone(), n),
                );
            }
        }
    };

    quote! {
        /// CPU compilation of the same function: per-segment min-reduce.
        pub fn cpu(#sig_args) -> Vec<#out_ty> {
            (0..seg_start.len() - 1)
                .map(|i| {
                    let mut best = <#out_ty>::MAX;
                    for k in seg_start[i]..seg_start[i + 1] {
                        let j = idx[k as usize] as usize;
                        let v = super::#name(#(#cn[j],)* #(#un),*);
                        if v < best { best = v; }
                    }
                    best
                })
                .collect()
        }
        #gpu
        #run
        #bind

        #[cfg(feature = "gpu")]
        mod gpu_impl {
            use cubecl::prelude::*;
            use cubecl::cuda::CudaRuntime;
            use crate::backend::cube::{client, contain, upload, read_out, CUBE_DIM};

            #session_gpu

            // ponytail: one thread per segment; degree skew serializes within a
            // thread. Upgrade path: warp-per-segment when profiles demand it.
            #[cube(launch_unchecked)]
            fn device(
                #(#cn: &Array<#ct>,)* idx: &Array<u32>, seg_start: &Array<u32>,
                init: #out_ty, #(#un: #ut,)* out: &mut Array<#out_ty>,
            ) {
                if ABSOLUTE_POS < out.len() {
                    let s = seg_start[ABSOLUTE_POS];
                    let e = seg_start[ABSOLUTE_POS + 1];
                    let mut best = init;
                    for k in s..e {
                        let j = idx[k as usize] as usize;
                        let v = super::super::#name(#(#cn[j],)* #(#un),*);
                        if v < best { best = v; }
                    }
                    out[ABSOLUTE_POS] = best;
                }
            }

            pub fn launch(
                #(#cn: &[#ct],)* idx: &[u32], seg_start: &[u32], #(#un: #ut),*
            ) -> Option<Vec<#out_ty>> {
                let client = client()?;
                let n = seg_start.len() - 1;
                if n == 0 { return Some(Vec::new()); }
                contain(|| {
                    #(let n_vals = #cn.len();)*
                    #(let #cn = upload(client, #cn);)*
                    let hidx = upload(client, idx);
                    let hseg = upload(client, seg_start);
                    let out = client.empty(n * core::mem::size_of::<#out_ty>());
                    unsafe {
                        device::launch_unchecked::<CudaRuntime>(
                            client,
                            CubeCount::Static((n as u32).div_ceil(CUBE_DIM), 1, 1),
                            CubeDim::new_1d(CUBE_DIM),
                            #(ArrayArg::from_raw_parts(#cn, n_vals),)*
                            ArrayArg::from_raw_parts(hidx, idx.len()),
                            ArrayArg::from_raw_parts(hseg, seg_start.len()),
                            <#out_ty>::MAX,
                            #(#un,)*
                            ArrayArg::from_raw_parts(out.clone(), n),
                        );
                    }
                    read_out::<#out_ty>(client, out, n)
                })
            }
        }
    }
}

fn gen_cross(
    name: &Ident,
    cols: &[&Param],
    uniforms: &[&Param],
    out_ty: &Type,
    self_pairs: bool,
) -> TokenStream2 {
    let half = cols.len() / 2;
    let a = &cols[..half];
    let an = names(a);
    let at = types(a);
    let un = names(uniforms);
    let ut = types(uniforms);
    let first = an[0].clone();

    let desc_ty: TokenStream2 = if self_pairs {
        quote! { (u32, u32) }
    } else {
        quote! { (u32, u32, u32, u32) }
    };

    let cpu_desc_loop = if self_pairs {
        quote! {
            let (s, e) = *desc;
            'outer: for u in s..e {
                for v in (u + 1)..e {
                    let (a, b) = (u as usize, v as usize);
                    if super::#name(#(#an[a],)* #(#an[b],)* #(#un),*) != 0 {
                        *flag = 1;
                        break 'outer;
                    }
                }
            }
        }
    } else {
        quote! {
            let (a0, a1, b0, b1) = *desc;
            'outer: for a in a0..a1 {
                for b in b0..b1 {
                    let (a, b) = (a as usize, b as usize);
                    if super::#name(#(#an[a],)* #(#an[b],)* #(#un),*) != 0 {
                        *flag = 1;
                        break 'outer;
                    }
                }
            }
        }
    };

    // Per-descriptor eval counts + chunk assembly differ between the two
    // cross flavors; the generated launcher enumerates the cross product on
    // device with an owner binary search, chunked to bound one launch.
    let (chunk_push, desc_total, device_index) = if self_pairs {
        (
            quote! {
                let (s, e) = descs[idx];
                starts_a.push(s);
                lens_b.push(e - s);
            },
            quote! { { let (s, e) = descs[idx]; ((e - s) as u64) * ((e - s) as u64) } },
            quote! {
                let el = lens_b[k as usize];
                let ur = local / el;
                let vr = local % el;
                let mut hit = 0u32;
                if vr > ur {
                    let a = (starts_a[k as usize] + ur) as usize;
                    let b = (starts_a[k as usize] + vr) as usize;
                    hit = super::super::#name(#(#an[a],)* #(#an[b],)* #(#un),*);
                }
            },
        )
    } else {
        (
            quote! {
                let (a0, _a1, b0, b1) = descs[idx];
                starts_a.push(a0);
                starts_b.push(b0);
                lens_b.push(b1 - b0);
            },
            quote! { { let (a0, a1, b0, b1) = descs[idx];
            ((a1 - a0) as u64) * ((b1 - b0) as u64) } },
            quote! {
                let bl = lens_b[k as usize];
                let a = (starts_a[k as usize] + local / bl) as usize;
                let b = (starts_b[k as usize] + local % bl) as usize;
                let hit = super::super::#name(#(#an[a],)* #(#an[b],)* #(#un),*);
            },
        )
    };

    let starts_b_decl = if self_pairs {
        quote! {}
    } else {
        quote! { let mut starts_b: Vec<u32> = Vec::new(); }
    };
    let starts_b_upload = if self_pairs {
        quote! {}
    } else {
        quote! { let hsb = upload(client, &starts_b); }
    };
    let starts_b_kernel_param = if self_pairs {
        quote! {}
    } else {
        quote! { starts_b: &Array<u32>, }
    };
    let starts_b_launch_arg = if self_pairs {
        quote! {}
    } else {
        quote! { ArrayArg::from_raw_parts(hsb, m), }
    };

    let sig_args = quote! { #(#an: &[#at],)* descs: &[#desc_ty], #(#un: #ut),* };
    let call_args = quote! { #(#an,)* descs, #(#un),* };

    let run = gen_run(&sig_args, &call_args, &syn::parse_quote!(u32));
    let gpu = gpu_stub(&sig_args, &call_args, &syn::parse_quote!(u32));
    let _ = out_ty; // cross shapes always produce per-descriptor u32 flags

    let prelude = session_cpu_prelude(&an, &at, &un, &ut);
    let (encode_fn, decode_fn): (TokenStream2, TokenStream2) = if self_pairs {
        (
            quote! { crate::session::encode_descs2 },
            quote! { crate::session::decode_descs2 },
        )
    } else {
        (
            quote! { crate::session::encode_descs4 },
            quote! { crate::session::decode_descs4 },
        )
    };
    let col_count = an.len();
    let ins_args = (0..col_count).map(|i| {
        quote! { ArrayArg::from_raw_parts(ins[#i].0.clone(), ins[#i].1), }
    });
    let uni_args = ut.iter().enumerate().map(|(i, t)| {
        quote! { uniforms.get::<#t>(#i), }
    });
    let bind = quote! {
        /// Session binding: columns stay on device; the (small, host-side)
        /// descriptor list rides in the bound kernel and is chunk-assembled
        /// at enqueue time exactly like the one-shot launcher.
        pub fn bind(
            #(#an: &crate::session::Col<#at>,)* descs: &[#desc_ty], #(#un: #ut),*
        ) -> crate::session::BoundKernel {
            crate::session::BoundKernel {
                cols: vec![#(#an.erased()),*],
                uniforms: crate::session::Uniforms::new()#(.push(#un))*,
                host: #encode_fn(descs),
                out_len: descs.len(),
                out_elem_size: core::mem::size_of::<u32>(),
                cpu_fn: session_cpu,
                #[cfg(feature = "gpu")]
                gpu_fn: gpu_impl::enqueue,
            }
        }

        fn session_cpu(
            store: &crate::session::CpuStore,
            cols: &[crate::session::ColRef],
            uniforms: &crate::session::Uniforms,
            host: &[u8],
            _out_len: usize,
        ) -> Vec<u8> {
            #prelude
            let descs = #decode_fn(host);
            let values = cpu(#(&#an,)* &descs, #(#un),*);
            {
                use crate::session::SessionElem;
                let mut bytes = Vec::with_capacity(values.len() * 4);
                for v in values {
                    v.write_to(&mut bytes);
                }
                bytes
            }
        }
    };
    let session_gpu = quote! {
        /// Session enqueue: zero the flag buffer, then chunked scatter-OR
        /// launches writing at `flag_base + k`. Never syncs.
        pub fn enqueue(
            client: &'static crate::backend::cube::Client,
            ins: &[(cubecl::server::Handle, usize)],
            out: (cubecl::server::Handle, usize),
            uniforms: &crate::session::Uniforms,
            host: &[u8],
        ) {
            let descs = #decode_fn(host);
            let n_flags = out.1;
            if n_flags == 0 { return; }
            unsafe {
                zero_fill::launch_unchecked::<CudaRuntime>(
                    client,
                    CubeCount::Static((n_flags as u32).div_ceil(CUBE_DIM), 1, 1),
                    CubeDim::new_1d(CUBE_DIM),
                    ArrayArg::from_raw_parts(out.0.clone(), n_flags),
                );
            }
            let mut idx = 0;
            let mut base: u32 = 0;
            while idx < descs.len() {
                let mut starts_a: Vec<u32> = Vec::new();
                #starts_b_decl
                let mut lens_b: Vec<u32> = Vec::new();
                let mut offs: Vec<u32> = Vec::new();
                let mut total: u64 = 0;
                while idx < descs.len() && (total as usize) < CHUNK {
                    offs.push(total as u32);
                    total += #desc_total;
                    #chunk_push
                    idx += 1;
                }
                let m = offs.len();
                let hsa = upload(client, &starts_a);
                #starts_b_upload
                let hlb = upload(client, &lens_b);
                let ho = upload(client, &offs);
                unsafe {
                    device::launch_unchecked::<CudaRuntime>(
                        client,
                        CubeCount::Static((total as u32).div_ceil(CUBE_DIM), 1, 1),
                        CubeDim::new_1d(CUBE_DIM),
                        #(#ins_args)*
                        ArrayArg::from_raw_parts(hsa, m),
                        #starts_b_launch_arg
                        ArrayArg::from_raw_parts(hlb, m),
                        ArrayArg::from_raw_parts(ho, m),
                        m as u32,
                        total as u32,
                        base,
                        #(#uni_args)*
                        ArrayArg::from_raw_parts(out.0.clone(), n_flags),
                    );
                }
                base += m as u32;
            }
        }
    };

    quote! {
        /// CPU compilation of the same function: per-descriptor OR-reduce.
        pub fn cpu(#sig_args) -> Vec<u32> {
            let mut flags = vec![0u32; descs.len()];
            for (desc, flag) in descs.iter().zip(flags.iter_mut()) {
                #cpu_desc_loop
            }
            flags
        }
        #gpu
        #run
        #bind

        #[cfg(feature = "gpu")]
        mod gpu_impl {
            use cubecl::prelude::*;
            use cubecl::cuda::CudaRuntime;
            use crate::backend::cube::{client, contain, upload, read_out, CHUNK, CUBE_DIM};

            #[cube]
            fn owner_of(off: &Array<u32>, n: u32, i: u32) -> u32 {
                let mut lo = 0u32;
                let mut hi = n - 1;
                while lo < hi {
                    let mid = (lo + hi + 1) / 2;
                    if off[mid as usize] <= i { lo = mid; } else { hi = mid - 1; }
                }
                lo
            }

            #[cube(launch_unchecked)]
            fn zero_fill(out: &mut Array<u32>) {
                if ABSOLUTE_POS < out.len() {
                    out[ABSOLUTE_POS] = 0u32;
                }
            }

            #session_gpu

            #[cube(launch_unchecked)]
            fn device(
                #(#an: &Array<#at>,)*
                starts_a: &Array<u32>, #starts_b_kernel_param lens_b: &Array<u32>,
                off: &Array<u32>, n_descs: u32, total: u32, flag_base: u32,
                #(#un: #ut,)*
                flags: &mut Array<u32>,
            ) {
                let i = ABSOLUTE_POS as u32;
                if i < total {
                    let k = owner_of(off, n_descs, i);
                    let local = i - off[k as usize];
                    #device_index
                    if hit != 0 { flags[(flag_base + k) as usize] = 1u32; }
                }
            }

            pub fn launch(#(#an: &[#at],)* descs: &[#desc_ty], #(#un: #ut),*) -> Option<Vec<u32>> {
                let client = client()?;
                if descs.is_empty() { return Some(Vec::new()); }
                contain(|| {
                    let n = #first.len();
                    #(let #an = upload(client, #an);)*
                    // two-phase: queue every chunk's kernel first, read results
                    // after — interleaving launch/read serializes the device.
                    let mut pending: Vec<(cubecl::server::Handle, usize)> = Vec::new();
                    let mut idx = 0;
                    while idx < descs.len() {
                        let mut starts_a: Vec<u32> = Vec::new();
                        #starts_b_decl
                        let mut lens_b: Vec<u32> = Vec::new();
                        let mut offs: Vec<u32> = Vec::new();
                        let mut total: u64 = 0;
                        while idx < descs.len() && (total as usize) < CHUNK {
                            offs.push(total as u32);
                            total += #desc_total;
                            #chunk_push
                            idx += 1;
                        }
                        let m = offs.len();
                        let hsa = upload(client, &starts_a);
                        #starts_b_upload
                        let hlb = upload(client, &lens_b);
                        let ho = upload(client, &offs);
                        let hf = upload(client, &vec![0u32; m]);
                        unsafe {
                            device::launch_unchecked::<CudaRuntime>(
                                client,
                                CubeCount::Static((total as u32).div_ceil(CUBE_DIM), 1, 1),
                                CubeDim::new_1d(CUBE_DIM),
                                #(ArrayArg::from_raw_parts(#an.clone(), n),)*
                                ArrayArg::from_raw_parts(hsa, m),
                                #starts_b_launch_arg
                                ArrayArg::from_raw_parts(hlb, m),
                                ArrayArg::from_raw_parts(ho, m),
                                m as u32,
                                total as u32,
                                0u32,
                                #(#un,)*
                                ArrayArg::from_raw_parts(hf.clone(), m),
                            );
                        }
                        pending.push((hf, m));
                    }
                    let mut flags = Vec::with_capacity(descs.len());
                    for (hf, m) in pending {
                        flags.extend(read_out::<u32>(client, hf, m)?);
                    }
                    Some(flags)
                })
            }
        }
    }
}
