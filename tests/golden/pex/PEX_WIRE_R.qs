exit 0
--- stdout
*SPEF "IEEE 1481-1998"
*DESIGN "tests/fixtures/pex/PEX_WIRE_R.gds"
*VENDOR "gpurify"
*PROGRAM "gpurify"
*VERSION "0.1.0"
// deck tests/fixtures/params.deck
*DESIGN_FLOW "EXTRACTED"
*DIVIDER /
*DELIMITER :
*BUS_DELIMITER [ ]
*T_UNIT 1 NS
*C_UNIT 1 FF
*R_UNIT 1 OHM
*L_UNIT 1 PH

*D_NET PEX_R_n0 0.204867
*CONN
*P PEX_R_n0 B
*CAP
1 PEX_R_n0:0 0.204867
*RES
1 PEX_R_n0:0 PEX_R_n0:1 1.000000
*INDUC
1 PEX_R_n0:0 PEX_R_n0:1 0.985668
*END

--- stderr
