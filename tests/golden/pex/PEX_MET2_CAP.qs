exit 0
--- stdout
*SPEF "IEEE 1481-1998"
*DESIGN "tests/fixtures/pex/PEX_MET2_CAP.gds"
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

*D_NET PEX_M2C_n0 0.223407
*CONN
*P PEX_M2C_n0 B
*CAP
1 PEX_M2C_n0:0 0.223407
*RES
*INDUC
*END

--- stderr
