# The KLayout side of tests/foundry (ledger F2): reads what the foundry
# drew and what its deck reported; it decides no verdict. Run as
# `klayout -b -r xcheck.rb -rd mode=<mode> -rd out=<file> ...`. Every mode
# writes tab-separated lines to $out, in database units of the layout.
#
# mode=prepare $gds $style [$cells] $manhattan
#   With $cells (a file naming one GDS per line), first writes $gds: every
#   top cell of those files on a grid 40 um apart, each a region
#   `cell <name>` that every rule must leave clean.
#   Without, reads $gds and finds its test structures by $style:
#     gf    pass boxes on 2/222 and fail boxes on 3/222 (or the 6/222 box
#           inside one), each named by the 11/222 text it holds, as the
#           gf180mcu fd_pv regression reads them (run_regression.py);
#     ihp   one row per rule text on 63/0 in the centre column, its half
#           left of the column under the PASS header and its half right
#           under the FAIL header, as IHP's unit cells are drawn;
#     pass, fail
#           the whole layout is one structure of rule $label;
#     whole the whole layout, its verdict the foundry deck's (`foundry`).
#   Writes `layer L D` per layer pair the layout holds, `region <kind>
#   <label> x1 y1 x2 y2` per structure, `odd x1 y1 x2 y2` per polygon
#   GPurify refuses (an edge off the axes, no area, or a boundary whose
#   merge is not itself: it crosses or overlaps itself; a keyhole merges
#   to itself), and $manhattan: the layout flattened, less every region
#   holding an odd polygon and less every odd polygon, for the rules (or
#   the whole layout) GPurify refuses on such geometry.
#
# mode=markers $gds $rdbs
#   `category <name>` per category of each report in $rdbs (comma
#   separated) and `marker <name> x1 y1 x2 y2` per value of each item.

$o = File.open($out, "w")
def put(*f) = $o.puts(f.join("\t"))
def box(b) = [b.left, b.bottom, b.right, b.top]

def flat(layout, top, l, d)
  li = layout.find_layer(l, d)
  r = RBA::Region.new
  r.insert(top.begin_shapes_rec(li)) if li
  r.merged
end

def texts(layout, top, l, d)
  li = layout.find_layer(l, d)
  out = []
  return out unless li
  it = top.begin_shapes_rec(li)
  until it.at_end?
    s = it.shape
    out << [s.text_string, s.text.transformed(it.trans).trans.disp] if s.is_text?
    it.next
  end
  out
end

def structures(layout, top)
  case $style
  when "gf"
    pass, fail, fail2 = flat(layout, top, 2, 222), flat(layout, top, 3, 222), flat(layout, top, 6, 222)
    out = []
    texts(layout, top, 11, 222).each do |name, p|
      holding = ->(r) { r.each.select { |poly| poly.inside?(p) } }
      holding.(pass).each { |poly| out << ["pass", name, poly.bbox] }
      holding.(fail).each do |poly|
        inner = fail2.each.select { |q| poly.bbox.overlaps?(q.bbox) }
        (inner.empty? ? [poly] : inner).each { |q| out << ["fail", name, q.bbox] }
      end
    end
    out
  when "ihp"
    all = texts(layout, top, 63, 0)
    head = all.select { |n, _| %w[PASS FAIL].include?(n) }.to_h
    raise "#{$gds}: no PASS and FAIL header on 63/0" unless head["PASS"] && head["FAIL"]
    split = (head["PASS"].x + head["FAIL"].x) / 2
    rows = all.reject { |n, p| head.key?(n) || p.y >= head["PASS"].y || (p.x - split).abs > 3000 }
              .sort_by { |_, p| -p.y }
    ext = top.bbox
    rows.each_with_index.flat_map do |(name, p), i|
      hi = i.zero? ? head["PASS"].y : (rows[i - 1][1].y + p.y) / 2
      lo = i == rows.size - 1 ? ext.bottom : (rows[i + 1][1].y + p.y) / 2
      [["pass", name, RBA::Box.new(ext.left, lo, split, hi)],
       ["fail", name, RBA::Box.new(split, lo, ext.right, hi)]]
    end
  when "pass", "fail"
    [[$style, $label, top.bbox]]
  when "whole"
    [["foundry", "-", top.bbox]]
  else
    raise "unknown style #{$style}"
  end
end

def sheet
  layout = RBA::Layout.new
  layout.dbu = 0.001
  top = layout.create_cell("SHEET")
  cells = []
  File.readlines($cells, chomp: true).reject(&:empty?).each do |f|
    src = RBA::Layout.new
    src.read(f)
    raise "#{f}: database unit #{src.dbu}" unless (src.dbu - 0.001).abs < 1e-9
    src.top_cells.each do |c|
      copy = layout.create_cell(c.name)
      copy.copy_tree(c)
      cells << copy
    end
  end
  cells.sort_by!(&:name)
  pitch = 40_000 + cells.map { |c| [c.bbox.width, c.bbox.height].max }.max
  per_row = Math.sqrt(cells.size).ceil
  found = cells.each_with_index.map do |c, i|
    at = RBA::Trans.new(RBA::Point.new((i % per_row) * pitch, (i / per_row) * pitch))
    top.insert(RBA::CellInstArray.new(c.cell_index, at))
    ["cell", c.name, c.bbox.transformed(at)]
  end
  layout.write($gds)
  [layout, top, found]
end

case $mode
when "prepare"
  if $cells
    layout, top, found = sheet
  else
    layout = RBA::Layout.new
    layout.read($gds)
    tops = layout.top_cells
    raise "#{$gds}: #{tops.size} top cells" unless tops.size == 1
    top = tops[0]
    found = structures(layout, top)
  end
  odd = ->(p) do
    next true if !p.is_rectilinear? || p.area.zero?
    m = RBA::Region.new(p).merged
    m.count != 1 || m.area != p.area
  end
  odd_boxes = []
  layout.layer_indexes.each do |li|
    i = layout.get_info(li)
    put("layer", i.layer, i.datatype)
    it = top.begin_shapes_rec(li)
    until it.at_end?
      s = it.shape
      if s.is_polygon? || s.is_box? || s.is_path?
        p = s.polygon.transformed(it.trans)
        odd_boxes << p.bbox if odd.(p)
      end
      it.next
    end
  end
  found.each { |kind, name, b| put("region", kind, name, *box(b)) }
  odd_boxes.each { |b| put("odd", *box(b)) }
  # The flattened copy GPurify reads where it refuses odd geometry.
  out = RBA::Layout.new
  out.dbu = layout.dbu
  flat_top = out.create_cell(top.name)
  cut = RBA::Region.new
  found.each { |_, _, b| cut.insert(b) if odd_boxes.any? { |a| a.overlaps?(b) || a.inside?(b) } }
  layout.layer_indexes.each do |li|
    i = layout.get_info(li)
    raw = RBA::Region.new(top.begin_shapes_rec(li))
    raw.merged_semantics = false
    raw = RBA::Region.new(raw.each.reject { |p| odd.(p) })
    raw.merged_semantics = false
    # Drawn polygons stay as drawn; only those reaching into a cut region are clipped.
    kept = cut.is_empty? ? raw : raw.outside(cut) + (raw.interacting(cut) - cut)
    into = flat_top.shapes(out.layer(i.layer, i.datatype))
    into.insert(kept)
    into.insert(RBA::Texts.new(top.begin_shapes_rec(li)))
  end
  out.write($manhattan)
when "markers"
  layout = RBA::Layout.new
  layout.read($gds)
  to_dbu = RBA::CplxTrans.new(layout.dbu).inverted
  $rdbs.split(",").each do |path|
    rdb = RBA::ReportDatabase.new("")
    rdb.load(path)
    names = {}
    rdb.each_category do |c|
      names[c.rdb_id] = c.path.delete("'")
      put("category", names[c.rdb_id])
    end
    # A deck run in deep mode reports in each cell's own coordinates; a
    # cell's references place it in its parents, up to the top.
    placements = Hash.new do |memo, id|
      refs = []
      rdb.cell_by_id(id).each_reference { |r| refs << [r.trans, r.parent_cell_id] }
      memo[id] = refs.empty? ? [RBA::DCplxTrans.new] : refs.flat_map { |t, up| memo[up].map { |p| p * t } }
    end
    rdb.each_item do |item|
      item.each_value do |v|
        b = if v.is_polygon? then v.polygon.bbox
            elsif v.is_box? then v.box
            elsif v.is_edge? then v.edge.bbox
            elsif v.is_edge_pair? then v.edge_pair.bbox
            elsif v.is_path? then v.path.bbox
            end
        next unless b
        placements[item.cell_id].each do |t|
          put("marker", names[item.category_id], *box(b.transformed(t).transformed(to_dbu)))
        end
      end
    end
  end
else
  raise "unknown mode #{$mode}"
end
$o.close
