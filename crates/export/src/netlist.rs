//! SPICE netlist export: the extracted circuit, optionally with its parasitics.
//!
//! The output of a whole run in the form a simulator can consume — extracted
//! devices from `topology`, and if asked, the parasitic R and C from `pex`
//! spliced into the nets between them.
//!
//! This is a *writer*, which is why it is here and not in `lvs`. In the old
//! tree it sat in `lvs` and dragged a `pex` dependency in behind it, so the
//! netlist comparator depended on parasitic extraction in order to write a file.

use std::fmt::Write as _;

use crate::json::format_f64;
use crate::parasitic::{first_node_of, node_name, spice_card};
use crate::{narrow, Header, WriteError, INFALLIBLE};
use gpurify_ingest::deck::DeviceKind;
use gpurify_ingest::StrTable;
use gpurify_pex::ParasiticNetwork;
use gpurify_topology::device::{DeviceId, DeviceMeasure, DeviceParam};
use gpurify_topology::{Extraction, NetId, PortTable, TerminalRole};

/// The subcircuit's name.
///
/// The signature carries no cell name — the extraction is one flat circuit, so
/// there is exactly one — and it must not come from `header.layout_path`,
/// because a path in a body is what the [`Header`] exists to keep out. `"TOP"`
/// is the name `engine` hands [`crate::gds::write_store`] for the same layout.
const CELL: &str = "TOP";

/// What an anonymous net's fallback name is lengthened by when a label has
/// already taken it — see [`net_name`].
///
/// Deliberately not a digit: that is what keeps `n7`, `n7_` and `n71` three
/// different names, so the fallback stays a one-to-one function of the
/// [`NetId`] no matter how many rounds of escaping a hostile label set forces.
const FALLBACK_PAD: char = '_';

/// Where a terminal sits on its family's SPICE card.
///
/// **Decision** — pure. The inverse of [`TerminalRole`]'s position-to-role
/// table: a recogniser lists a MOS gate first, a SPICE card names the drain
/// first, and a writer that emitted them in table order would produce a file
/// that simulates a different transistor. One global table rather than one per
/// family, because the roles are already family-specific — only a MOS has a
/// gate, only a BJT has a base.
const fn card_rank(role: TerminalRole) -> u8 {
    match role {
        // `Mname nd ng ns nb`.
        TerminalRole::Drain | TerminalRole::Collector => 0,
        TerminalRole::Gate | TerminalRole::Base => 1,
        TerminalRole::Source | TerminalRole::Emitter => 2,
        TerminalRole::Bulk => 3,
        // Symmetric two-terminal: the position *is* the rank, which is what
        // `Pin`'s payload means, so table order survives unchanged.
        TerminalRole::Pin(position) => position,
    }
}

/// What to include.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Detail {
    /// Devices and their connectivity only. What LVS compares, and what a
    /// functional simulation needs.
    Schematic,
    /// Devices plus lumped per-net parasitic R and C. What a timing-accurate
    /// simulation needs.
    WithParasitics,
}

/// Write the extracted circuit as a SPICE subcircuit.
///
/// **Transform.** Caller owns `out`, appended to.
///
/// Devices are emitted in ascending `DeviceId`, which is canonical because
/// `topology` assigns ids by sorting on the marker polygon. Nets are named
/// through `ports` where they have a name and by their `NetId` where they do
/// not — and a `NetId` is canonical too, being the minimum polygon index in the
/// component. So the whole file is a function of the layout, with nothing
/// depending on the order anything was discovered in.
///
/// `parasitics` is `None` for [`Detail::Schematic`]. Passing a network and
/// asking for `Schematic` writes the schematic — the parameter is the source,
/// the mode is the decision, and they are separate so neither implies the other.
pub fn write_spice(
    extraction: Extraction<'_>,
    parasitics: Option<&ParasiticNetwork>,
    detail: Detail,
    strings: &StrTable,
    header: &Header,
    out: &mut String,
) -> Result<(), WriteError> {
    let (nets, devices, ports) = (extraction.nets, extraction.devices, extraction.ports);
    let device_count = devices.len();
    let net_count = nets.net_count();
    debug_assert_eq!(
        devices.terminal_start.len(),
        device_count + 1,
        "the terminal CSR carries one offset per device plus a terminator"
    );
    debug_assert_eq!(
        devices.param_start.len(),
        device_count + 1,
        "the param CSR carries one offset per device plus a terminator"
    );
    debug_assert_eq!(
        devices.terminal_net.len(),
        devices.terminal_role.len(),
        "a net column and a role column arrive parallel"
    );
    // No entry assert that `ports.len() <= net_count`: it is the same claim the
    // pin loop below settles exactly, and settles as a typed error rather than a
    // panic, so asserting it here would abort the one path a test of that
    // refusal has to walk.

    // Appended to, never indexed from zero: a caller may write several netlists
    // into one buffer, and the second must be the bytes it would have been alone.
    let before = out.len();

    // The parameter is the source, the mode is the decision. `Schematic` does
    // not read `parasitics` at all, so handing one over cannot change a byte.
    let spliced = parasitics.filter(|_| detail == Detail::WithParasitics);

    writeln!(out, "* {} SPICE netlist", header.tool_version).expect(INFALLIBLE);
    writeln!(out, "* deck: {}", header.deck_path).expect(INFALLIBLE);
    writeln!(out, "* layout: {}", header.layout_path).expect(INFALLIBLE);
    // Passed in, never read from the clock, and absent when the caller has none
    // — the header is the only place a run's metadata is allowed to be.
    if let Some(stamp) = &header.timestamp {
        writeln!(out, "* written: {stamp}").expect(INFALLIBLE);
    }
    // Not a `Grid` this signature holds, so not a unit it can name. Recorded
    // open in `docs/SIGNATURE_DEFECTS.md`; stating the ambiguity in the file is
    // what keeps a simulator from silently reading database units as metres.
    writeln!(out, "* lengths below are in database units").expect(INFALLIBLE);

    // ponytail: `O(nets · log ports)`, because `PortTable` publishes none of
    // its four columns and `name_of` — a binary search — is the only way to read
    // one. The port list is the named nets in ascending `NetId`, and named nets
    // are a cell's pins, hundreds against a net count in the millions, so the
    // scan is the wrong way round. Only the `log ports` factor is debt: a merge
    // of the port column against `0 .. net_count` is one linear pass and needs
    // no search at all. The `O(nets)` factor stays either way, because this loop
    // also has to emit nothing for every unnamed net.
    //
    // Not reducible from inside this body. `PortTable`'s whole surface is
    // `name_of`, `net_of`, `len` and `is_empty`; every one answers membership at
    // a point and none answers "how many ports below this net", so there is no
    // rank to gallop on and no way to narrow the next search with what the last
    // one returned, even though the queries arrive in ascending order against an
    // ascending column. And the one route that sidesteps `net_count` — walk
    // `StrTable`'s dense ids and ask `PortTable::net_of` about each — answers
    // with the *lower* net when one label reaches two, so it would drop a pin.
    //
    // Same missing accessor `crates/lvs/src/graph.rs:239` is blocked on, and it
    // takes the same fix: `fn entries(&self) -> (&[NetId], &[StrId])` on
    // `PortTable`, or the `net`/`name` columns made `pub`. Frozen signature, so
    // it is filed rather than taken. Six sites across three crates want it, this
    // one of them; `## PortTable has no enumerable surface, third pass` in
    // `docs/SIGNATURE_DEFECTS.md` is the consolidated record and supersedes the
    // `## export` and `export/netlist.rs` spend-down sections on the count.
    //
    // Loop shape: map over nets, appending the named ones, with `pins` the
    // reduction that makes the omission below detectable.
    out.push_str(".subckt ");
    out.push_str(CELL);
    let mut pins = 0usize;
    for net in 0..net_count {
        let net = NetId(narrow(net));
        let named = ports.name_of(net).is_some();
        // The count carries the decision rather than the control flow, so it is
        // exact whichever way the branch resolves.
        pins += usize::from(named);
        // A surviving `if`: it predicts well in the direction that matters —
        // nearly every net of a real cell is internal — and the taken side
        // resolves a name and appends it, which is the expensive side a branch
        // exists to skip.
        if named {
            out.push(' ');
            // Through the same naming the device cards use, or a pin would be
            // declared on a node nothing inside the subcircuit references —
            // `VDD` on the header line against `VDD:0` on every device — and
            // the port would be floating in a file that still simulates. In
            // `Schematic` the two are the same string, so this line is
            // unchanged there.
            put_terminal_node(net, spliced, ports, strings, out)?;
        }
    }
    out.push('\n');

    debug_assert!(
        pins <= ports.len(),
        "{} nets answered to a name out of {} bindings, so one net is bound twice",
        pins,
        ports.len()
    );
    // Fail closed. A binding whose `NetId` is not in `0..net_count` — the
    // `NetId::NONE` sentinel, or a table built against a different extraction —
    // is never reached by the scan above, so its pin is simply absent from the
    // `.subckt` line while every device card still names the node. The result is
    // a port silently demoted to an internal node, in a file that parses,
    // simulates, and answers a different circuit. The count is the only evidence
    // this interface can produce that the scan saw every binding, so it is the
    // check: fewer pins than bindings is unrepresentable, not clean.
    if pins != ports.len() {
        return Err(WriteError::Unrepresentable(
            "a port bound to a net outside the extraction",
        ));
    }

    // Terminals reordered onto their card positions, one device at a time. Four
    // entries at most, hoisted so a million devices reuse one allocation.
    let mut card: Vec<(u8, NetId)> = Vec::new();

    // Scalar, and structurally so rather than as a shortcut. The output is a
    // byte stream whose length depends on the row, so row N's output offset is
    // the sum of every row before it — a loop-carried chain, where
    // `/simd-loops` triage stops. There is no upgrade path to hold open here.
    for device in 0..device_count {
        let id = DeviceId(narrow(device));
        let (terminal_net, terminal_role) = devices.terminals_of(id);

        // A closed match on a family tag. Not the data-dependent branch the
        // kernel rule is about: five variants lower to a jump table, and the
        // decimal formatting either side of it costs an order of magnitude more.
        let letter = match devices.kind[device] {
            DeviceKind::Mos => 'M',
            DeviceKind::Bjt => 'Q',
            DeviceKind::Resistor => 'R',
            DeviceKind::Capacitor => 'C',
            DeviceKind::Diode => 'D',
        };
        // The instance name is the `DeviceId`, which is the rank of the marker
        // polygon and so canonical for a layout. Parasitic elements below carry
        // a `p` in the same slot, so an extracted `R0` and a parasitic `Rp0`
        // cannot collide.
        write!(out, "{letter}{device}").expect(INFALLIBLE);

        card.clear();
        card.extend(
            terminal_role
                .iter()
                .zip(terminal_net)
                .map(|(&role, &net)| (card_rank(role), net)),
        );
        // Stable, so two terminals of one rank stay in the order the recogniser
        // stated them and the file is a function of the tables alone.
        card.sort_by_key(|&(rank, _)| rank);
        debug_assert_eq!(
            card.len(),
            terminal_net.len(),
            "reordering a device's terminals onto its card dropped one"
        );
        for &(_, net) in &card {
            out.push(' ');
            put_terminal_node(net, spliced, ports, strings, out)?;
        }

        out.push(' ');
        out.push_str(strings.resolve(devices.model[device]));

        // A handful of measured parameters per device, not bulk.
        for &(param, measure) in devices.params_of(id) {
            let key = match param {
                DeviceParam::Width => "w",
                DeviceParam::Length => "l",
                DeviceParam::Area => "area",
                DeviceParam::Perimeter => "perim",
                DeviceParam::Fingers => "nf",
            };
            // Integers, exactly as measured: these are `Dbu` and `DbuArea`, and
            // routing them through `format_f64` would round a coordinate to make
            // it look like a physical quantity it has no `Grid` to become.
            match measure {
                DeviceMeasure::Length(value) => write!(out, " {key}={}", value.raw()),
                DeviceMeasure::Area(value) => write!(out, " {key}={}", value.raw()),
                DeviceMeasure::Count(value) => write!(out, " {key}={value}"),
            }
            .expect(INFALLIBLE);
        }
        out.push('\n');
    }

    if let Some(network) = spliced {
        let elements = network.element_count();

        // Every element is emitted as extracted rather than lumped, so nothing
        // is dropped and no topology is invented. The device cards above name
        // their terminals through `put_terminal_node`, so both sides of the
        // file address the same nodes by the same text.
        //
        // Raw loop, for the device loop's reason.
        for row in 0..elements {
            // Through the same decision `write_dspf` cards an element with, so
            // the two files agree about both the letter and the scale factor.
            // The slot is that writer's per-prefix counter; here the element row
            // numbers the card, so `Rp0` and `Cp1` are the network's own rows.
            let (letter, _, magnitude, suffix) = spice_card(network.value[row]);
            write!(out, "{letter}p{row} ").expect(INFALLIBLE);
            node_name(network, network.from[row], ports, strings, out)?;
            out.push(' ');
            match network.to[row] {
                Some(node) => node_name(network, node, ports, strings, out)?,
                // SPICE's ground. A `None` far end is a capacitance to it, not
                // a node the network forgot to name.
                None => out.push('0'),
            }
            out.push(' ');
            format_f64(magnitude, out);
            out.push_str(suffix);
            out.push('\n');
        }

        debug_assert_eq!(
            network.element_count(),
            elements,
            "a writer transcribes; it does not change the network it was given"
        );
    }

    writeln!(out, ".ends {CELL}").expect(INFALLIBLE);

    debug_assert!(
        out.len() > before,
        "a netlist with a header and a subcircuit cannot be empty"
    );
    Ok(())
}

/// Append the SPICE node a device terminal sits on.
///
/// **Decision** — pure, appended to `out`.
///
/// Without parasitics this is the net's name and there is nothing else it could
/// be. With them, the nodes of a net are named `net:index` and the bare net name
/// is not one of them, so a card that kept using it would leave every device
/// terminal on a node no parasitic element touches — an RC network hanging off
/// nothing and devices seeing no parasitics, in a file that still parses and
/// still simulates. Terminals therefore attach at their net's *first* node.
///
/// That is a stated lumping and not a measurement: `ParasiticNetwork` carries no
/// terminal-to-node column, so which node a given source or drain actually sits
/// on is not knowable from this signature. Filed in `docs/SIGNATURE_DEFECTS.md`
/// under `pex`; the upgrade is that column, not a body here.
fn put_terminal_node(
    net: NetId,
    spliced: Option<&ParasiticNetwork>,
    ports: &PortTable,
    strings: &StrTable,
    out: &mut String,
) -> Result<(), WriteError> {
    // Not a bulk branch either way: `spliced` is constant for the whole call, so
    // the predictor has it after the first terminal, and a net the extraction
    // produced no parasitics for has no node to name — its terminals still meet
    // each other on the plain net name, which is exactly the schematic.
    let node = spliced.and_then(|network| Some((network, first_node_of(network, net)?)));
    if let Some((network, node)) = node {
        node_name(network, node, ports, strings, out)
    } else {
        net_name(net, ports, strings, out);
        Ok(())
    }
}

/// The name of one net in the emitted netlist.
///
/// **Decision** — pure. Shared with the parasitic writers so a net has one name
/// across every file a run produces.
pub fn net_name(
    net: gpurify_topology::NetId,
    ports: &PortTable,
    strings: &StrTable,
    out: &mut String,
) {
    // Fail closed. `NetId::NONE` is an absence, not a net — nothing is on it,
    // and a writer asking it for a name has already lost track of which net it
    // is naming. There is no error channel here, so this is the loudest the
    // signature allows; in release it still produces a distinct name rather
    // than silently reusing another net's.
    debug_assert_ne!(
        net,
        gpurify_topology::NetId::NONE,
        "asked for the name of no net at all"
    );

    let before = out.len();
    // Not a bulk branch: one lookup per net, and the taken side resolves and
    // copies a string. SPICE names an anonymous net by number, unlike SPEF,
    // where an unnamed net is an error rather than a fallback.
    if let Some(name) = ports.name_of(net) {
        out.push_str(strings.resolve(name));
    } else {
        write!(out, "n{}", net.0).expect(INFALLIBLE);
        // A layout whose label is literally `n7` would otherwise be handed
        // the fallback name of net 7 as well, shorting two nets in a file
        // that is still valid SPICE and still simulates. The label space
        // and the fallback space meet here and nowhere else, so the
        // collision is settled here: lengthen the fallback until no port
        // carries it. `FALLBACK_PAD` is not a digit, so `n7`, `n7_` and `n71`
        // stay three distinct names and the fallback stays injective over
        // `NetId` however many rounds it takes.
        //
        // Cost is one interner binary search per anonymous net, and it
        // misses for every text no label ever spelled — which is nearly
        // every fallback. `PortTable::net_of`'s scan runs only when a label
        // with this exact text exists in the table at all.
        while strings
            .get(&out[before..])
            .is_some_and(|taken| ports.net_of(taken).is_some())
        {
            out.push(FALLBACK_PAD);
        }
    }

    debug_assert!(
        out.len() > before,
        "net {} came back with an empty name, which no netlist can carry",
        net.0
    );
    debug_assert!(
        strings
            .get(&out[before..])
            .and_then(|name| ports.net_of(name))
            .is_none_or(|owner| owner == net),
        "net {} was named {:?}, which is net {:?}'s label",
        net.0,
        &out[before..],
        strings.get(&out[before..]).and_then(|n| ports.net_of(n))
    );
}
