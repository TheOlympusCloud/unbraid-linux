//! The welcome, before anything else on a new install: the idea, the four places, then what to know before starting.

use crate::APP;
use std::f64::consts::PI;
use std::fmt::Write;

/// A page's head and its lead paragraph ("" for none).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct WelcomeStep {
    pub overline: String,
    pub title: String,
    pub lead: String,
}

/// One strand of the braid in its 342 × 230 box, as SVG path commands: a whole strand, or the piece of one that goes
/// over the other at a crossing (`front`). `colour`: 0 the accent (top), 1 the second route colour, 2 Direct's.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Strand {
    pub path: String,
    pub colour: i32,
    pub front: bool,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct WelcomeView {
    /// The three pages: the idea, the four places, what to know before starting.
    pub steps: Vec<WelcomeStep>,
    /// The braid on the first page, drawn in this order.
    pub strands: Vec<Strand>,
}

pub fn view() -> WelcomeView {
    let step = |overline: &str, title: &str, lead: String| WelcomeStep {
        overline: overline.into(),
        title: title.into(),
        lead,
    };
    WelcomeView {
        steps: vec![
            step("Welcome", "Every app, its own exit", "Your bank direct, streaming through another country, everything else private. All at once, from one switch.".into()),
            step("Four places", "Find your way", format!("Everything {APP} does lives in one of four places.")),
            step("Good to know", "Before you start", String::new()),
        ],
        strands: braid(),
    }
}

/// Three strands braided together leave the computer, then part for their exits: the name, drawn. In a 342 × 230 box:
/// the three whole strands first, then a front piece at every crossing.
pub fn braid() -> Vec<Strand> {
    fn smooth(a: f32, b: f32, x: f32) -> f32 {
        let t = ((x - a) / (b - a)).clamp(0.0, 1.0);
        t * t * (3.0 - 2.0 * t)
    }
    let (x0, xb, cy) = (22f32, 150f32, 115f32);
    let k = (2.0 * PI / 76.0) as f32;
    let phase: [f32; 3] = std::array::from_fn(|i| (i as f64 * 2.0 * PI / 3.0) as f32);
    let raw = |i: usize, x: f32| 30.0 * smooth(x0, x0 + 30.0, x) * ((k * (x - x0) + phase[i]) as f64).sin() as f32;
    // Each strand ends where it leaves the braid: top, middle, bottom.
    let mut order = [0, 1, 2];
    order.sort_by(|&a, &b| raw(a, xb + 12.0).total_cmp(&raw(b, xb + 12.0)));
    let (mut target, mut colour) = ([0f32; 3], [0i32; 3]);
    for (r, &s) in order.iter().enumerate() {
        target[s] = [34.0, 115.0, 196.0][r];
        colour[s] = r as i32;
    }
    let xs: Vec<f32> = (0..=320).map(|i| x0 + i as f32).collect();
    let last = xs.len() - 1;
    let ys: Vec<Vec<f32>> = (0..3)
        .map(|i| {
            xs.iter()
                .map(|&x| {
                    cy + (1.0 - smooth(xb - 10.0, xb + 34.0, x)) * raw(i, x)
                        + smooth(xb, xb + 150.0, x) * (target[i] - cy)
                })
                .collect()
        })
        .collect();
    let path = |i: usize, from: isize, to: usize| {
        let (a, b) = (from.max(0) as usize, to.min(last));
        let mut d = String::new();
        for j in a..=b {
            let _ = write!(d, "{}{:.2} {:.2} ", if j == a { "M" } else { "L" }, xs[j], ys[i][j]);
        }
        d.trim_end().to_string()
    };
    let mut out: Vec<Strand> =
        (0..3).map(|i| Strand { path: path(i, 0, last), colour: colour[i], front: false }).collect();
    // At every crossing the strand moving towards the third goes over: a real three-strand plait.
    for (a, b) in [(0, 1), (0, 2), (1, 2)] {
        let c = 3 - a - b;
        for j in 0..last {
            let (d0, d1) = (ys[a][j] - ys[b][j], ys[a][j + 1] - ys[b][j + 1]);
            if d0 == 0.0 || d0 * d1 < 0.0 {
                let f = if (ys[c][j] - ys[a][j]) * (ys[a][j + 1] - ys[a][j]) > 0.0 { a } else { b };
                out.push(Strand { path: path(f, j as isize - 10, j + 10), colour: colour[f], front: true });
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The idea, the four places, and what to know before starting.
    #[test]
    fn words_for_each_page() {
        let v = view();
        let heads: Vec<_> = v.steps.iter().map(|s| (s.overline.as_str(), s.title.as_str())).collect();
        assert_eq!(
            vec![
                ("Welcome", "Every app, its own exit"),
                ("Four places", "Find your way"),
                ("Good to know", "Before you start")
            ],
            heads
        );
        assert_eq!("Everything unbraid does lives in one of four places.", v.steps[1].lead);
        assert_eq!("", v.steps[2].lead);
    }

    fn points(path: &str) -> Vec<(f32, f32)> {
        path.split(['M', 'L'])
            .filter(|p| !p.trim().is_empty())
            .map(|p| {
                let mut n = p.split_whitespace().map(|v| v.parse::<f32>().unwrap());
                (n.next().unwrap(), n.next().unwrap())
            })
            .collect()
    }

    /// The three strands leave the computer together at (22, 115) and end at their exits, the accent on top, then
    /// the second route colour, then Direct; the crossings are short front pieces, after the strands they cover.
    #[test]
    fn braid_leaves_together_and_parts_for_three_exits() {
        let strands = braid();
        let whole: Vec<_> = strands.iter().take_while(|s| !s.front).collect();
        assert_eq!(3, whole.len());
        let mut ends: Vec<_> = whole
            .iter()
            .map(|s| {
                let p = points(&s.path);
                assert_eq!(321, p.len());
                assert_eq!((22.0, 115.0), p[0]);
                (s.colour, *p.last().unwrap())
            })
            .collect();
        ends.sort_by_key(|e| e.0);
        assert_eq!(vec![(0, (342.0, 34.0)), (1, (342.0, 115.0)), (2, (342.0, 196.0))], ends);
        let fronts = &strands[3..];
        assert!(fronts.len() > 10 && fronts.iter().all(|s| s.front), "{} crossings", fronts.len());
        assert!(
            fronts.iter().all(|s| (11..=21).contains(&points(&s.path).len()) && points(&s.path)[0].0 < 150.0 + 34.0)
        );
    }
}
