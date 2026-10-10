ly = RBA::Layout.new; ly.dbu = 0.001
top = ly.create_cell("TOP")
l1 = ly.layer(1,0); l2 = ly.layer(2,0); l9 = ly.layer(9,0)
[[0,0,100,100],[100,100,200,200],[400,0,501,1000],[600,0,700,1000],[760,0,860,1000]].each { |b| top.shapes(l1).insert(RBA::Box.new(*b)) }
[[650,500,700,600]].each { |b| top.shapes(l2).insert(RBA::Box.new(*b)) }
top.shapes(l9).insert(RBA::Box.new(0,0,1000,1000))
ly.write("mirror_t.gds")
