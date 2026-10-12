//! Structural Verilog over a SPICE cell library (catalog LVS-075): each
//! construct of the subset against the SPICE hierarchy that states the same
//! connections, and the refusals.

use gpurify_geom::StrTable;
use gpurify_ingest::deck::DeviceRecognition;
use gpurify_ingest::netlist::{spice, verilog, Netlist, NetlistError};

/// The cell library: an inverter `INV A Y VDD VSS` and a cell with a bus
/// port, `REG D[1] D[0] Q VDD VSS`.
const CELLS: &str = "\
.subckt INV A Y VDD VSS
M0 Y A VSS VSS nfet
M1 Y A VDD VDD pfet
.ends
.subckt REG D[1] D[0] Q VDD VSS
M0 Q D[1] VSS VSS nfet
M1 Q D[0] VDD VDD pfet
.ends
";

/// `netlist` flattened below `top`: its port names in order, and every
/// device as its model and terminal net names, sorted.
fn flat(
    netlist: &Netlist,
    top: Option<gpurify_ingest::netlist::SubcktId>,
    strings: &mut StrTable,
) -> (Vec<String>, Vec<Vec<String>>) {
    let top = top.expect("a unique top");
    let flat = netlist.flatten_top(top, strings).expect("it flattens");
    let name = |id: gpurify_ingest::netlist::RefNetId| {
        strings.resolve(flat.net_name[id.0 as usize]).to_owned()
    };
    let ports = flat.port_net.iter().map(|&n| name(n)).collect();
    let mut devices: Vec<Vec<String>> = (0..flat.device_model.len())
        .map(|d| {
            let range =
                flat.device_terminal_start[d] as usize..flat.device_terminal_start[d + 1] as usize;
            std::iter::once(strings.resolve(flat.device_model[d]).to_owned())
                .chain(flat.terminal_net[range].iter().map(|&n| name(n)))
                .collect()
        })
        .collect();
    devices.sort();
    (ports, devices)
}

/// `verilog` read over the library, flattened.
fn from_verilog(verilog_text: &str) -> Result<(Vec<String>, Vec<Vec<String>>), NetlistError> {
    let mut strings = StrTable::default();
    let mut netlist = spice::read(CELLS, &mut strings, &DeviceRecognition::default())?;
    let modules = verilog::read_into(&[verilog_text], &mut strings, &mut netlist)?;
    let top = netlist.top_in(modules);
    Ok(flat(&netlist, top, &mut strings))
}

/// `top`, SPICE `X` cards over the library, flattened.
fn from_spice(top: &str) -> (Vec<String>, Vec<Vec<String>>) {
    let mut strings = StrTable::default();
    let netlist = spice::read(
        &format!("{CELLS}{top}"),
        &mut strings,
        &DeviceRecognition::default(),
    )
    .expect("the SPICE twin reads");
    let modules = u32::try_from(netlist.subckt_count()).expect("few");
    let top = netlist.top_in(2..modules);
    flat(&netlist, top, &mut strings)
}

/// Oracle: the SPICE hierarchy stating the same connections (IEEE 1364-2005
/// §12.3.6: a port connected by name takes that connection, by position the
/// one in its place; Netgen reads either as the `X` card below). Two
/// inverters in a chain, one connected by name in any order and one in
/// order, an `assign` joining the output to a second port, and a bus
/// connected to a cell's bit ports: the flattened devices and ports equal
/// the SPICE twin's. Breaks if a named connection lands by position, a bus
/// bit lands on the wrong pin, or an assign does not join.
#[test]
fn a_verilog_top_flattens_as_its_spice_twin() {
    let verilog_text = "\
// a comment
(* top *)
module TOP (a, y, y2, d, VDD, VSS);
  input a; output y, y2; input [1:0] d;
  inout VDD, VSS;
  wire m;
  INV u1 (.Y(m), .VDD(VDD), .A(a), .VSS(VSS));
  INV u2 (m, y, VDD, VSS); /* in order */
  REG r1 (.D(d), .Q(q), .VDD(VDD), .VSS(VSS));
  assign y2 = y;
endmodule
";
    let spice_text = "\
.subckt TOP a y y2 d[1] d[0] VDD VSS
Xu1 a m VDD VSS INV
Xu2 m y VDD VSS INV
Xr1 d[1] d[0] q VDD VSS REG
.ends
";
    let (ports, devices) = from_verilog(verilog_text).expect("the subset reads");
    let (want_ports, mut want) = from_spice(spice_text);
    // `assign y2 = y` makes one net, named by the lesser name.
    for device in &mut want {
        for net in device.iter_mut() {
            if net == "y2" {
                *net = "y".to_owned();
            }
        }
    }
    want.sort();
    assert_eq!(devices, want);
    let mut joined = want_ports;
    for port in &mut joined {
        if port == "y2" {
            *port = "y".to_owned();
        }
    }
    assert_eq!(ports, joined);
}

/// Oracle: IEEE 1364-2005 (ports declared in place, §12.3.4; a part select
/// and a concatenation as connections, §5.2.1 and §5.1.14; an escaped
/// identifier, §3.7.1; an unconnected port, §12.3.6) against the SPICE twin.
/// The bus is wired reversed through a concatenation, one inverter's supply
/// is left open (its own net, `u1.VSS`), and an escaped name is the plain
/// one. Breaks if a concatenation keeps the wrong order or an open port
/// joins another net.
#[test]
fn ports_in_place_concatenations_and_open_ports_read_as_written() {
    let verilog_text = "\
module TOP (input [1:0] d, output \\q , inout VDD, VSS);
  wire [1:0] x;
  REG r1 (.D({d[0], d[1]}), .Q(x[1]), .VDD(VDD), .VSS(VSS));
  INV u1 (.A(x[1]), .Y(q), .VDD(VDD), .VSS());
endmodule
";
    let spice_text = "\
.subckt TOP d[1] d[0] q VDD VSS
Xr1 d[0] d[1] x[1] VDD VSS REG
Xu1 x[1] q VDD u1.VSS INV
.ends
";
    assert_eq!(
        from_verilog(verilog_text).expect("the subset reads"),
        from_spice(spice_text)
    );
}

/// Oracle: the module docs' refusals, each stated by construction. A
/// directive, a constant, a parameter, an instance array, behavioural code,
/// a cell defined nowhere, a port the cell lacks, a bus of the wrong width,
/// too few ordered connections, and a module named as a cell it does not
/// merely declare are each refused with the variant the docs name; an empty
/// stub declaring a library cell is read. Breaks if any is read as
/// something else.
#[test]
fn what_the_subset_leaves_out_is_refused() {
    let wrap = |body: &str| format!("module TOP (a, y, VDD, VSS);\n{body}\nendmodule\n");
    let unsupported = [
        "`ifdef USE_POWER_PINS\n`endif".to_owned(),
        wrap("INV u1 (.A(1'b0), .Y(y), .VDD(VDD), .VSS(VSS));"),
        wrap("INV #(1) u1 (a, y, VDD, VSS);"),
        wrap("INV u1 [1:0] (a, y, VDD, VSS);"),
        wrap("reg r;"),
        wrap("always @(a) y = a;"),
    ];
    for text in &unsupported {
        assert!(
            matches!(from_verilog(text), Err(NetlistError::Unsupported(..))),
            "{text}: {:?}",
            from_verilog(text)
        );
    }
    assert!(matches!(
        from_verilog(&wrap("NAND u1 (a, y, VDD, VSS);")),
        Err(NetlistError::UndefinedSubckt(..))
    ));
    for text in [
        wrap("INV u1 (.B(a), .Y(y), .VDD(VDD), .VSS(VSS));"),
        wrap("wire [2:0] w;\nREG r1 (.D(w), .Q(y), .VDD(VDD), .VSS(VSS));"),
        wrap("INV u1 (.A(a), .A(y), .VDD(VDD), .VSS(VSS));"),
    ] {
        assert!(
            matches!(from_verilog(&text), Err(NetlistError::Unexpected(..))),
            "{text}"
        );
    }
    assert!(matches!(
        from_verilog(&wrap("INV u1 (a, y, VDD);")),
        Err(NetlistError::TerminalCount(..))
    ));
    let redefined = format!(
        "module INV (A, Y, VDD, VSS);\nassign Y = A;\nendmodule\n{}",
        wrap("INV u1 (a, y, VDD, VSS);")
    );
    assert!(matches!(
        from_verilog(&redefined),
        Err(NetlistError::Redefined(..))
    ));
    let stub = format!(
        "module INV (A, Y, VDD, VSS);\ninput A;\nendmodule\n{}",
        wrap("INV u1 (a, y, VDD, VSS);")
    );
    let (_, devices) = from_verilog(&stub).expect("a stub declares the cell");
    assert_eq!(devices.len(), 2, "the library's inverter, placed once");
}
