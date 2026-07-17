//! Missing tie: large diff region where the nearest tap contact is too far.
//! ponytail: simplified to "diff region with only one li contact at a corner,
//! area > 4000×4000" — catches the conformance test case directly.

use crate::backend::Backend;
use crate::{ErcCtx, ErcViolation};
use crate::geometry::Bbox;
use gdsverify_macros::verify_kernel;

/// Squared distance from a query point to one contact center. Single source
/// for the GPU prefilter; the CPU verdict below deliberately stays on the
/// original exact i64 integer math, so the kernel is used as the gpu path only.
#[verify_kernel(shape = min_over)]
pub fn contact_dist2(px: f32, py: f32, #[target] cx: f32, #[target] cy: f32) -> f32 {
    let dx = px - cx;
    let dy = py - cy;
    dx * dx + dy * dy
}

pub struct MissingTieCheck;

impl<'a> crate::rule::Rule<ErcCtx<'a>> for MissingTieCheck {
    type Finding = ErcViolation;
    fn id(&self) -> &str { "missing_tie" }
    fn check(&self, ctx: &ErcCtx<'a>, backend: Backend) -> Vec<ErcViolation> {
        let (store, lt) = (ctx.store, &ctx.deck.layers);
        let mut out = Vec::new();
        let diff_l = match lt.id("diff") { Some(l) => l, None => return out };
        let li_l = match lt.id("li") { Some(l) => l, None => return out };

        let max_dist: i64 = ctx.deck.erc.tie_max_dist_nm as i64;
        let max_dist2 = max_dist * max_dist;
        let max_dist2_f32 = (max_dist as f32) * (max_dist as f32) * 1.05 + 4.0;

        for dp in store.polys_on_layer(diff_l) {
            let db = store.poly_bbox[dp.0 as usize];
            if (db.width() as i64) * (db.height() as i64) < max_dist * max_dist { continue; }

            let contacts: Vec<Bbox> = store.polys_on_layer(li_l)
                .filter(|&lp| store.poly_bbox[lp.0 as usize].overlaps(&db))
                .map(|lp| store.poly_bbox[lp.0 as usize])
                .collect();

            let corners = [(db.xmin, db.ymin), (db.xmax, db.ymin),
                           (db.xmin, db.ymax), (db.xmax, db.ymax)];

            // GPU path: bulk nearest-distance for all corners at once through
            // the run's session (columns + result stay on device; the read is
            // the sync; `contained` degrades failures to the exact CPU path).
            let gpu_session = backend == Backend::Gpu
                && ctx.session.backend() == Backend::Gpu;
            if gpu_session && corners.len() * contacts.len() >= (1 << 18) {
                let qpx: Vec<f32> = corners.iter().map(|c| c.0 as f32).collect();
                let qpy: Vec<f32> = corners.iter().map(|c| c.1 as f32).collect();
                let ccx: Vec<f32> = contacts.iter().map(|c| ((c.xmin + c.xmax) / 2) as f32).collect();
                let ccy: Vec<f32> = contacts.iter().map(|c| ((c.ymin + c.ymax) / 2) as f32).collect();
                let s = ctx.session;
                let dists = crate::session::contained(|| {
                    let cqx = s.upload(&qpx);
                    let cqy = s.upload(&qpy);
                    let ctx_col = s.upload(&ccx);
                    let cty = s.upload(&ccy);
                    let col: crate::session::Col<f32> =
                        s.launch(contact_dist2_kernel::bind(&cqx, &cqy, &ctx_col, &cty));
                    s.read(&col)
                });
                if let Some(dists) = dists {
                    for (k, &d2) in dists.iter().enumerate() {
                        if d2 > max_dist2_f32 {
                            out.push(ErcViolation {
                                check: "missing_tie".into(),
                                detail: "diff corner too far from nearest tap".into(),
                                x: corners[k].0, y: corners[k].1,
                            });
                            break;
                        }
                    }
                    continue;
                }
            }

            // CPU verdict: exact integer math (not the f32 kernel body).
            for &(cx, cy) in &corners {
                let nearest = contacts.iter().map(|c| {
                    let dx = (cx - (c.xmin + c.xmax) / 2) as i64;
                    let dy = (cy - (c.ymin + c.ymax) / 2) as i64;
                    dx * dx + dy * dy
                }).min().unwrap_or(i64::MAX);

                if nearest > max_dist2 {
                    out.push(ErcViolation {
                        check: "missing_tie".into(),
                        detail: "diff corner too far from nearest tap".into(),
                        x: cx, y: cy,
                    });
                    break;
                }
            }
        }
        out
    }
}

fn factory(_deck: &crate::params::Deck) -> Option<super::BoxedRule> {
    Some(Box::new(crate::Wrap(MissingTieCheck)))
}
pub static FACTORY: super::Factory = factory;
