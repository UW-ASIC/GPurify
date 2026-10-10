exit 0
--- stdout
*SPEF "IEEE 1481-1998"
*DESIGN "tests/fixtures/pex/PEX_PLATE_C.gds"
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

*D_NET PEX_C_n0 0.223407
*CONN
*P PEX_C_n0 B
*CAP
1 PEX_C_n0:0 0.223407
*RES
1 PEX_C_n0:0 PEX_C_n0:1 0.100000
*INDUC
1 PEX_C_n0:0 PEX_C_n0:1 0.233915
*END

--- stderr
