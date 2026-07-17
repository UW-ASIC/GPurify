//! Fast-fail check: NPN/PNP device counts must match before any graph
//! refinement is attempted. Runs after the MOS count check.

use crate::backend::Backend;
use crate::rules::Factory;
use crate::types::{DeviceKind, Mismatch};
use crate::LvsCtx;
use crate::rule::Rule;

pub struct DeviceCountBjtRule;

impl<'a> Rule<LvsCtx<'a>> for DeviceCountBjtRule {
    type Finding = Mismatch;
    fn id(&self) -> &str { "device_count_bjt" }
    fn check(&self, ctx: &LvsCtx<'a>, _backend: Backend) -> Vec<Mismatch> {
        let ext_npn = ctx.extracted.bjt_devices.iter().filter(|d| d.kind == DeviceKind::Npn).count();
        let ext_pnp = ctx.extracted.bjt_devices.iter().filter(|d| d.kind == DeviceKind::Pnp).count();
        let ref_npn = ctx.reference.ref_bjt.iter().filter(|d| d.kind == DeviceKind::Npn).count();
        let ref_pnp = ctx.reference.ref_bjt.iter().filter(|d| d.kind == DeviceKind::Pnp).count();

        let mut findings = Vec::new();
        if ext_npn != ref_npn {
            findings.push(Mismatch::DeviceCount {
                kind: "Npn".into(), extracted: ext_npn, reference: ref_npn,
            });
        }
        if ext_pnp != ref_pnp {
            findings.push(Mismatch::DeviceCount {
                kind: "Pnp".into(), extracted: ext_pnp, reference: ref_pnp,
            });
        }
        if !findings.is_empty() {
            ctx.fail(format!(
                "device count mismatch (ext {}NPN/{}PNP vs ref {}NPN/{}PNP)",
                ext_npn, ext_pnp, ref_npn, ref_pnp));
        }
        findings
    }
}

pub const FACTORY: Factory = |_opts| Some(Box::new(DeviceCountBjtRule));
