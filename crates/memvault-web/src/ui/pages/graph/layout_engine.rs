//! Force-directed graph layout engine with clustering.
//!
//! Pure Rust, WASM-compatible. Runs tick-by-tick in a Dioxus `use_effect`.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// A node in the force graph.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GraphNode {
    pub id: String,
    pub kind: String,
    pub label: String,
    pub x: f64,
    pub y: f64,
    pub vx: f64,
    pub vy: f64,
    /// Fixed position (set during drag). None = free.
    pub fx: Option<f64>,
    pub fy: Option<f64>,
    pub radius: f64,
}

/// An edge between two nodes (by index into the nodes vec).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GraphEdge {
    pub source: usize,
    pub target: usize,
    pub relation: String,
    pub weight: f32,
}

/// User-adjustable forces. Sane defaults match the values the simulation
/// shipped with before the controls existed; the explorer surfaces these
/// as sliders so the layout can be tuned without recompiling.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct ForceParams {
    /// Spring constant for edge "links" (higher = tighter).
    pub link_strength: f64,
    /// Rest length of a link spring in world units.
    pub link_distance: f64,
    /// Pull toward (0, 0). Scales with alpha.
    pub center_strength: f64,
    /// Coulomb-style many-body repulsion. Positive = repulsive (a node is
    /// pushed away from every other node; see `tick`'s repulsion loop).
    pub repulsion_strength: f64,
}

impl Default for ForceParams {
    fn default() -> Self {
        Self {
            link_strength: 0.08,
            link_distance: 200.0,
            center_strength: 0.01,
            repulsion_strength: 2000.0,
        }
    }
}

/// Force simulation state.
pub struct ForceSimulation {
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
    pub alpha: f64,
    pub alpha_decay: f64,
    pub alpha_min: f64,
    pub velocity_decay: f64,
    pub params: ForceParams,
}

impl ForceSimulation {
    pub fn new() -> Self {
        Self {
            nodes: Vec::new(),
            edges: Vec::new(),
            alpha: 1.0,
            alpha_decay: 0.02,
            alpha_min: 0.001,
            velocity_decay: 0.4,
            params: ForceParams::default(),
        }
    }

    /// Add a node. Returns its index. If a node with the same ID exists, returns that index.
    pub fn add_node(&mut self, id: String, kind: String, label: String) -> usize {
        if let Some(idx) = self.nodes.iter().position(|n| n.id == id) {
            return idx;
        }
        // Place new nodes on a golden-angle spiral with generous spacing so the
        // simulation starts from a spread-out state rather than a tight clump.
        let i = self.nodes.len() as f64;
        let angle = i * 2.399_963; // golden angle in radians
        let r = 120.0 + i.sqrt() * 160.0;
        let idx = self.nodes.len();
        self.nodes.push(GraphNode {
            id,
            kind,
            label,
            x: angle.cos() * r,
            y: angle.sin() * r,
            vx: 0.0,
            vy: 0.0,
            fx: None,
            fy: None,
            radius: 16.0,
        });
        idx
    }

    /// Add an edge between two node indices.
    pub fn add_edge(&mut self, source: usize, target: usize, relation: String, weight: f32) {
        // Don't add duplicate edges.
        if self
            .edges
            .iter()
            .any(|e| e.source == source && e.target == target && e.relation == relation)
        {
            return;
        }
        self.edges.push(GraphEdge {
            source,
            target,
            relation,
            weight: weight.max(0.1),
        });
        // Scale node radius by edge count.
        self.nodes[source].radius = 14.0 + (self.edge_count(source) as f64).sqrt() * 4.0;
        self.nodes[target].radius = 14.0 + (self.edge_count(target) as f64).sqrt() * 4.0;
    }

    fn edge_count(&self, node: usize) -> usize {
        self.edges
            .iter()
            .filter(|e| e.source == node || e.target == node)
            .count()
    }

    /// Whether the simulation has settled.
    pub fn is_settled(&self) -> bool {
        self.alpha < self.alpha_min
    }

    /// Reheat the simulation (e.g. after a drag or new nodes).
    pub fn reheat(&mut self) {
        self.alpha = 0.3;
    }

    /// Run one simulation tick.
    pub fn tick(&mut self) {
        if self.is_settled() {
            return;
        }

        let n = self.nodes.len();
        if n == 0 {
            return;
        }

        // ── Many-body repulsion (Coulomb-like, N^2) ───────────────────
        // Constant structural force that keeps nodes apart.
        let repulsion_strength = self.params.repulsion_strength;
        let min_dist_sq = 900.0; // 30px minimum distance
        for i in 0..n {
            for j in (i + 1)..n {
                let dx = self.nodes[j].x - self.nodes[i].x;
                let dy = self.nodes[j].y - self.nodes[i].y;
                let dist_sq = (dx * dx + dy * dy).max(min_dist_sq);
                let dist = dist_sq.sqrt();
                let force = repulsion_strength / dist_sq;
                let fx = dx / dist * force;
                let fy = dy / dist * force;
                self.nodes[i].vx -= fx;
                self.nodes[i].vy -= fy;
                self.nodes[j].vx += fx;
                self.nodes[j].vy += fy;
            }
        }

        // ── Clustering force ─────────────────────────────────────────
        // Pulls nodes toward the centroid of their kind-group.
        // Creates visual clusters without preventing cross-kind edges.
        let cluster_strength = 0.15 * self.alpha;
        let mut centroids: HashMap<String, (f64, f64, usize)> = HashMap::new();
        for node in &self.nodes {
            let entry = centroids.entry(node.kind.clone()).or_insert((0.0, 0.0, 0));
            entry.0 += node.x;
            entry.1 += node.y;
            entry.2 += 1;
        }
        for node in &mut self.nodes {
            if let Some(&(cx, cy, count)) = centroids.get(&node.kind) {
                if count > 1 {
                    let avg_x = cx / count as f64;
                    let avg_y = cy / count as f64;
                    node.vx += (avg_x - node.x) * cluster_strength;
                    node.vy += (avg_y - node.y) * cluster_strength;
                }
            }
        }

        // ── Link spring force ─────────────────────────────────────────
        // Pulls connected nodes toward link_distance apart.
        let link_distance = self.params.link_distance;
        let link_strength = self.params.link_strength;
        for edge in &self.edges {
            let dx = self.nodes[edge.target].x - self.nodes[edge.source].x;
            let dy = self.nodes[edge.target].y - self.nodes[edge.source].y;
            let dist = (dx * dx + dy * dy).sqrt().max(1.0);
            let displacement = dist - link_distance;
            let force = displacement * link_strength * self.alpha;
            let fx = dx / dist * force;
            let fy = dy / dist * force;
            self.nodes[edge.source].vx += fx;
            self.nodes[edge.source].vy += fy;
            self.nodes[edge.target].vx -= fx;
            self.nodes[edge.target].vy -= fy;
        }

        // ── Centering force ───────────────────────────────────────────
        let center_strength = self.params.center_strength * self.alpha;
        for node in &mut self.nodes {
            node.vx -= node.x * center_strength;
            node.vy -= node.y * center_strength;
        }

        // ── Collision avoidance ───────────────────────────────────────
        for i in 0..n {
            for j in (i + 1)..n {
                let dx = self.nodes[j].x - self.nodes[i].x;
                let dy = self.nodes[j].y - self.nodes[i].y;
                let dist = (dx * dx + dy * dy).sqrt().max(0.1);
                let min_sep = self.nodes[i].radius + self.nodes[j].radius + 20.0;
                if dist < min_sep {
                    let push = (min_sep - dist) * 0.5;
                    let px = dx / dist * push;
                    let py = dy / dist * push;
                    self.nodes[i].vx -= px;
                    self.nodes[i].vy -= py;
                    self.nodes[j].vx += px;
                    self.nodes[j].vy += py;
                }
            }
        }

        // ── Apply velocity and damping ────────────────────────────────
        for node in &mut self.nodes {
            if let Some(fx) = node.fx {
                node.x = fx;
                node.vx = 0.0;
            } else {
                node.vx *= self.velocity_decay;
                node.vx = node.vx.clamp(-50.0, 50.0);
                node.x += node.vx;
            }
            if let Some(fy) = node.fy {
                node.y = fy;
                node.vy = 0.0;
            } else {
                node.vy *= self.velocity_decay;
                node.vy = node.vy.clamp(-50.0, 50.0);
                node.y += node.vy;
            }
        }

        // Decay alpha.
        self.alpha += (self.alpha_min - self.alpha) * self.alpha_decay;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Settle a 2-node, 1-edge graph at the given link rest length and
    /// return the final inter-node distance.
    fn settle_distance(link_distance: f64) -> f64 {
        let mut s = ForceSimulation::new();
        let a = s.add_node("a".into(), "k".into(), "A".into());
        let b = s.add_node("b".into(), "k".into(), "B".into());
        s.add_edge(a, b, "rel".into(), 1.0);
        s.params.link_distance = link_distance;
        s.alpha = 1.0;
        // Runs until alpha decays below alpha_min (tick early-returns after).
        for _ in 0..3000 {
            s.tick();
        }
        let dx = s.nodes[a].x - s.nodes[b].x;
        let dy = s.nodes[a].y - s.nodes[b].y;
        (dx * dx + dy * dy).sqrt()
    }

    #[test]
    fn link_distance_controls_separation() {
        let short = settle_distance(80.0);
        let long = settle_distance(320.0);
        assert!(
            long > short,
            "longer link_distance should separate nodes more: long={long} short={short}"
        );
    }
}
