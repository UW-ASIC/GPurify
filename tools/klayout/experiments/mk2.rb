ly = RBA::Layout.new; ly.dbu = 0.001
top = ly.create_cell("TOP")
l1 = ly.layer(1,0)
[[0,0,100,100],[100,100,200,200]].each { |b| top.shapes(l1).insert(RBA::Box.new(*b)) }
top.shapes(l1).insert(RBA::Polygon.new(RBA::Box.new(400,0,800,400)).insert_hole(RBA::Box.new(500,100,700,300)))
ly.write("mirror_h.gds")
