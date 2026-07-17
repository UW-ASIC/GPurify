//! Parametric check: W/L of matched MOS devices must agree within the deck
//! tolerances. Skipped entirely in legacy mode (any reference W/L of 0).
//!
//! Devices are bucketed by refined class and compared in sorted (W, L) order;
//! the first out-of-tolerance pair fails fatally, like the old inline code.

use std::collections::BTreeMap;

use crate::backend::Backend;
use crate::rules::Factory;
use crate::types::Mismatch;
use crate::LvsCtx;
use crate::rule::Rule;

pub struct ParametricRule;

impl<'a> Rule<LvsCtx<'a>> for ParametricRule {
    type Finding = Mismatch;
    fn id(&self) -> &str { "parametric" }
    fn check(&self, ctx: &LvsCtx<'a>, _backend: Backend) -> Vec<Mismatch> {
        let enforce_parametric = ctx.reference.devices.iter().all(|d| d.w > 0 && d.l > 0);
        if !enforce_parametric {
            return Vec::new();
        }
        let r = ctx.refined.expect("parametric rule runs post-refinement");

        // Bucket MOS devices by their final class
        let mut ext_wl: BTreeMap<u32, Vec<(i32, i32)>> = BTreeMap::new();
        let mut ref_wl: BTreeMap<u32, Vec<(i32, i32)>> = BTreeMap::new();
        for (i, d) in r.ga.devs.iter().enumerate() {
            if !d.is_mos { continue; }
            let oi = d.orig_idx as usize;
            ext_wl.entry(r.dev_cls_a[i]).or_default()
                .push((ctx.extracted.devices[oi].w, ctx.extracted.devices[oi].l));
        }
        for (i, d) in r.gb.devs.iter().enumerate() {
            if !d.is_mos { continue; }
            let oi = d.orig_idx as usize;
            ref_wl.entry(r.dev_cls_b[i]).or_default()
                .push((ctx.reference.devices[oi].w, ctx.reference.devices[oi].l));
        }

        let opts = ctx.opts;
        let within_w = |got: i32, expect: i32| -> bool {
            ((got - expect).abs() as f64)
                <= (opts.w_tolerance.abs_nm as f64).max(opts.w_tolerance.rel_pct * expect as f64)
        };
        let within_l = |got: i32, expect: i32| -> bool {
            ((got - expect).abs() as f64)
                <= (opts.l_tolerance.abs_nm as f64).max(opts.l_tolerance.rel_pct * expect as f64)
        };
        for (cls, exts) in ext_wl.iter_mut() {
            if let Some(refs) = ref_wl.get_mut(cls) {
                exts.sort_unstable();
                refs.sort_unstable();
                for (&(gw, gl), &(rw, rl)) in exts.iter().zip(refs.iter()) {
                    if !within_w(gw, rw) || !within_l(gl, rl) {
                        ctx.fail(format!(
                            "parametric mismatch: expected W/L {}/{} got {}/{}",
                            rw, rl, gw, gl));
                        return vec![Mismatch::ParametricMismatch {
                            property: "W/L".into(),
                            got: gw as f64,
                            expected: rw as f64,
                            tolerance: opts.w_tolerance.abs_nm as f64,
                        }];
                    }
                }
            }
        }
        Vec::new()
    }
}

pub const FACTORY: Factory = |_opts| Some(Box::new(ParametricRule));
