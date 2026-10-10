# helpers: build an in-memory layout and make it the DRC source
def mk(spec)
  ly = RBA::Layout.new
  ly.dbu = 0.001
  top = ly.create_cell("TOP")
  spec.each do |ld, shapes|
    li = ly.layer(ld[0], ld[1])
    shapes.each do |s|
      if s.is_a?(Array) && s[0].is_a?(Array)
        top.shapes(li).insert(RBA::Polygon.new(s.map { |x, y| RBA::Point.new(x, y) }))
      elsif s.is_a?(String)
        x, y, t = s.split(",")
        top.shapes(li).insert(RBA::Text.new(t, RBA::Trans.new(x.to_i, y.to_i)))
      else
        top.shapes(li).insert(RBA::Box.new(*s))
      end
    end
  end
  ly
end
def use(spec)
  $ly = mk(spec)
  source($ly, "TOP")
end
def ep_s(ep)
  r = []
  ep.data.each { |e| r << "#{e.first} | #{e.second} d=#{e.distance}" }
  r.join("; ")
end
def show(name, layer)
  d = layer.data
  n = layer.count
  items = []
  d.each { |o| items << o.to_s } if n < 12
  puts "#{name}: count=#{n} #{items.join(' ; ')}"
end
flat

# T1 width equality
use({[1,0] => [[0,0,100,1000]]})
a = input(1,0)
show("T1 width(100)", a.width(100))
