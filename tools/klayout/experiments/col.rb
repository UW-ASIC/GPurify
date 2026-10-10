ly = RBA::Layout.new; ly.dbu = 0.001
top = ly.create_cell("TOP"); l1 = ly.layer(1,0)
pts = [[0,0],[0,100],[50,100],[100,100],[100,0]].map { |x,y| RBA::Point.new(x,y) }
p = RBA::Polygon.new(pts, true)
top.shapes(l1).insert(p)
puts "inserted: #{top.shapes(l1).each.first.polygon}"
ly.write("col.gds")
ly2 = RBA::Layout.new; ly2.read("col.gds")
ly2.top_cell.shapes(ly2.layer(1,0)).each { |s| puts "read back: #{s.polygon} raw-edges=#{RBA::Region.new(s.polygon).edges.count}" }
r = RBA::Region.new(ly2.top_cell.begin_shapes_rec(ly2.layer(1,0)))
puts "region raw ongrid(3) points: #{r.dup.tap { |x| x.merged_semantics = false }.grid_check(3,3).count}"
