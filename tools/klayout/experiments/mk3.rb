ly = RBA::Layout.new; ly.dbu = 0.001
top = ly.create_cell("TOP"); l1 = ly.layer(1,0)
top.shapes(l1).insert(RBA::Box.new(0,0,100,100))
top.shapes(l1).insert(RBA::Text.new("X", RBA::Trans.new(50,50)))
ly.write("mirror_p.gds")
