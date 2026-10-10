exit 0
--- stdout
*SPEF "IEEE 1481-1998"
*DESIGN "tests/fixtures/pex/PEX_VIA_R.gds"
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

*D_NET PEX_VIA1_n0 0.168684
*CONN
*P PEX_VIA1_n0 B
*CAP
1 PEX_VIA1_n0:0 0.168684
*RES
*INDUC
*END

--- stderr
