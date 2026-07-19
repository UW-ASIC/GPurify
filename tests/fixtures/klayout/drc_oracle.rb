# frozen_string_literal: true

# Independent KLayout-native oracle for the rule families whose semantics map
# directly to Region checks. Invoke with KLayout in batch mode:
#
#   GPUVERIFY_GDS=... GPUVERIFY_RULE=min_width GPUVERIFY_CASE=... \
#     klayout -b -r drc_oracle.rb

require "json"

input_path = ENV.fetch("GPUVERIFY_GDS")
rule = ENV.fetch("GPUVERIFY_RULE")
case_id = ENV.fetch("GPUVERIFY_CASE")

layout = RBA::Layout.new
layout.read(input_path)
top = layout.top_cell
raise "input has no top cell" if top.nil?

def region(layout, top, layer, datatype = 0)
  RBA::Region.new(top.begin_shapes_rec(layout.layer(layer, datatype)))
end

met1 = region(layout, top, 7)
met2 = region(layout, top, 9)

markers = case rule
          when "min_width"
            met1.width_check(100)
          when "min_spacing"
            # GPUVerify intentionally separates inter-polygon spacing from
            # intra-polygon notch checks. KLayout's isolated check is the same
            # inter-polygon operation.
            met1.isolated_check(100)
          when "min_spacing_diff"
            met1.separation_check(met2, 100)
          when "min_enclosure"
            outer, inner = if case_id.start_with?("DRC_WE_")
                             [region(layout, top, 1), region(layout, top, 2)]
                           else
                             [met1, met2]
                           end
            # KLayout emits one edge-pair per failing side, while GPUVerify's
            # public report emits one marker per inner polygon and also reports
            # an entirely unhosted inner. Normalize only that cardinality; both
            # containment and distance verdicts remain KLayout-native.
            failing_inner = 0
            inner.each_merged do |polygon|
              candidate = RBA::Region.new
              candidate.insert(polygon)
              hosted = candidate.inside(outer).count == 1
              margin_failed = outer.enclosing_check(candidate, 50).count.positive?
              failing_inner += 1 if !hosted || margin_failed
            end
            failing_inner
          when "min_area"
            met1.with_area(nil, 40_000, false)
          when "max_width"
            # The engine's slotting trigger is the smaller bounding-box
            # dimension and fires strictly above 5000 DBU.
            met1.with_bbox_min(5001, nil, false)
          when "notch"
            met1.notch_check(100)
          when "off_grid"
            all = RBA::Region.new
            layout.layer_indices.each do |layer_index|
              all.insert(top.begin_shapes_rec(layer_index))
            end
            all.grid_check(5, 5)
          when "overlap"
            met1.overlap_check(met2, 50)
          else
            raise "unsupported KLayout oracle rule #{rule.inspect}"
          end

count = markers.is_a?(Integer) ? markers : markers.count
puts "GPUVERIFY_KLAYOUT #{JSON.generate({case: case_id, rule: rule, count: count})}"
