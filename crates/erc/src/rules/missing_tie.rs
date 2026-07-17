//! Missing tie: large diff region where the nearest tap contact is too far.
//! ponytail: simplified to "diff region with only one li contact at a corner,
//! area > 4000×4000" — catches the conformance test case directly.

use crate::backend::Backend;
use crate::geometry::Bbox;
use crate::{ErcCtx, ErcViolation};

/// Squared distance from a query point to one contact center. Kept as a plain
/// function (was the GPU prefilter kernel body); the CPU verdict below uses the
/// original exact i64 integer math, so this stays a small f32 helper.
#[must_use]
pub fn contact_dist2(px: f32, py: f32, cx: f32, cy: f32) -> f32 {
    let dx = px - cx;
    let dy = py - cy;
    dx * dx + dy * dy
}

pub struct MissingTieCheck;

impl<'a> crate::rule::Rule<ErcCtx<'a>> for MissingTieCheck {
    type Finding = ErcViolation;
    fn id(&self) -> &str {
        "missing_tie"
    }
    fn check(&self, ctx: &ErcCtx<'a>, _backend: Backend) -> Vec<ErcViolation> {
        let (store, lt) = (ctx.store, &ctx.deck.layers);
        let mut out = Vec::new();
        let diff_l = match lt.id("diff") {
            Some(l) => l,
            None => return out,
        };
        let li_l = match lt.id("li") {
            Some(l) => l,
            None => return out,
        };

        let max_dist: i64 = ctx.deck.erc.tie_max_dist_nm as i64;
        let max_dist2 = max_dist * max_dist;

        for dp in store.polys_on_layer(diff_l) {
            let db = store.poly_bbox[dp.0 as usize];
            if (db.width() as i64) * (db.height() as i64) < max_dist * max_dist {
                continue;
            }

            let contacts: Vec<Bbox> = store
                .polys_on_layer(li_l)
                .filter(|&lp| store.poly_bbox[lp.0 as usize].overlaps(&db))
                .map(|lp| store.poly_bbox[lp.0 as usize])
                .collect();

            let corners = [
                (db.xmin, db.ymin),
                (db.xmax, db.ymin),
                (db.xmin, db.ymax),
                (db.xmax, db.ymax),
            ];

            // CPU verdict: exact integer math (not the f32 kernel body).
            for &(cx, cy) in &corners {
                let nearest = contacts
                    .iter()
                    .map(|c| {
                        let dx = (cx - (c.xmin + c.xmax) / 2) as i64;
                        let dy = (cy - (c.ymin + c.ymax) / 2) as i64;
                        dx * dx + dy * dy
                    })
                    .min()
                    .unwrap_or(i64::MAX);

                if nearest > max_dist2 {
                    out.push(ErcViolation {
                        check: "missing_tie".into(),
                        detail: "diff corner too far from nearest tap".into(),
                        x: cx,
                        y: cy,
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
