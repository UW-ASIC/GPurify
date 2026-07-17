//! Axis-aligned bounding box.

/// An axis-aligned bounding box, kept alongside polygons for fast reject
/// (hot/cold split: the bbox is hot for spatial queries, the full vertex list
/// is colder).
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Bbox {
    pub xmin: i32,
    pub ymin: i32,
    pub xmax: i32,
    pub ymax: i32,
}

impl Bbox {
    /// The empty box: `include` on it yields exactly the included points.
    #[must_use]
    #[inline]
    pub fn empty() -> Self {
        Bbox {
            xmin: i32::MAX,
            ymin: i32::MAX,
            xmax: i32::MIN,
            ymax: i32::MIN,
        }
    }

    /// Grow the box to contain `(x, y)`.
    #[inline]
    pub fn include(&mut self, x: i32, y: i32) {
        self.xmin = self.xmin.min(x);
        self.ymin = self.ymin.min(y);
        self.xmax = self.xmax.max(x);
        self.ymax = self.ymax.max(y);
    }

    /// Width as `i64` (overflow-safe; the exact/validation path uses this).
    #[must_use]
    #[inline]
    pub fn width_i64(&self) -> i64 {
        i64::from(self.xmax) - i64::from(self.xmin)
    }

    /// Height as `i64` (overflow-safe).
    #[must_use]
    #[inline]
    pub fn height_i64(&self) -> i64 {
        i64::from(self.ymax) - i64::from(self.ymin)
    }

    /// Compatibility span for APIs whose declared coordinate capacity is `i32`.
    /// Full-range boxes saturate instead of overflowing; exact code must use
    /// [`Self::width_i64`].
    #[must_use]
    #[inline]
    pub fn width(&self) -> i32 {
        self.width_i64().clamp(i64::from(i32::MIN), i64::from(i32::MAX)) as i32
    }

    /// See [`Self::width`].
    #[must_use]
    #[inline]
    pub fn height(&self) -> i32 {
        self.height_i64().clamp(i64::from(i32::MIN), i64::from(i32::MAX)) as i32
    }

    /// Do two boxes come within `dist` of each other? Prunes spacing pairs.
    #[must_use]
    #[inline]
    pub fn within(&self, o: &Bbox, dist: i32) -> bool {
        let dist = i64::from(dist);
        i64::from(self.xmin) - dist <= i64::from(o.xmax)
            && i64::from(o.xmin) - dist <= i64::from(self.xmax)
            && i64::from(self.ymin) - dist <= i64::from(o.ymax)
            && i64::from(o.ymin) - dist <= i64::from(self.ymax)
    }

    /// Do two boxes touch or overlap?
    #[must_use]
    #[inline]
    pub fn overlaps(&self, o: &Bbox) -> bool {
        self.within(o, 0)
    }

    /// Smallest box covering both. [`Self::empty`] is the identity.
    #[must_use]
    #[inline]
    pub fn union(&self, o: &Bbox) -> Bbox {
        Bbox {
            xmin: self.xmin.min(o.xmin),
            ymin: self.ymin.min(o.ymin),
            xmax: self.xmax.max(o.xmax),
            ymax: self.ymax.max(o.ymax),
        }
    }

    /// Overlap region, `None` when disjoint. Zero-width/height touching regions
    /// are returned, matching [`Self::overlaps`].
    #[must_use]
    #[inline]
    pub fn intersection(&self, o: &Bbox) -> Option<Bbox> {
        if !self.overlaps(o) {
            return None;
        }
        Some(Bbox {
            xmin: self.xmin.max(o.xmin),
            ymin: self.ymin.max(o.ymin),
            xmax: self.xmax.min(o.xmax),
            ymax: self.ymax.min(o.ymax),
        })
    }

    /// Box of a point sequence; [`Self::empty`] for an empty iterator.
    #[must_use]
    pub fn from_points(pts: impl IntoIterator<Item = (i32, i32)>) -> Bbox {
        let mut bb = Bbox::empty();
        for (x, y) in pts {
            bb.include(x, y);
        }
        bb
    }
}
