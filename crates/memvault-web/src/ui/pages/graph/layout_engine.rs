//! Force-directed graph layout engine.
//!
//! Pure Rust, WASM-compatible. Runs tick-by-tick in a Dioxus `use_effect`.

use serde::{Deserialize, Serialize};

/// A node in the force graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphEdge {
    pub source: usize,
    pub target: usize,
    pub relation: String,
    pub weight: f32,
}

/// Force simulation state.
pub struct ForceSimulation {
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
    pub alpha: f64,
    pub alpha_decay: f64,
    pub alpha_min: f64,
    pub velocity_decay: f64,
}

impl ForceSimulation {
    pub fn new() -> Self {
        Self {
            nodes: Vec::new(),
            edges: Vec::new(),
            alpha: 1.0,
            alpha_decay: 0.028,
            alpha_min: 0.001,
            velocity_decay: 0.4,
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
        let r = 80.0 + i.sqrt() * 120.0;
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
        // Repulsion is NOT scaled by alpha — it provides a constant structural
        // force that keeps nodes apart. Only the spring and centering forces
        // decay with alpha so the layout converges without collapsing.
        let repulsion_strength = -600.0;
        // Minimum separation to avoid division-by-zero and extreme forces.
        let min_dist_sq = 400.0; // = 20px minimum distance
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

        // ── Link spring force ─────────────────────────────────────────
        // Pulls connected nodes toward link_distance apart.
        // Scaled by alpha so it weakens as the system cools.
        let link_distance = 150.0;
        let link_strength = 0.15;
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
        // Very gentle pull toward the origin to keep the graph on-screen.
        // Only affects the center of mass, not individual node separation.
        let center_strength = 0.01 * self.alpha;
        for node in &mut self.nodes {
            node.vx -= node.x * center_strength;
            node.vy -= node.y * center_strength;
        }

        // ── Collision avoidance ───────────────────────────────────────
        // Push overlapping nodes apart based on their radii.
        for i in 0..n {
            for j in (i + 1)..n {
                let dx = self.nodes[j].x - self.nodes[i].x;
                let dy = self.nodes[j].y - self.nodes[i].y;
                let dist = (dx * dx + dy * dy).sqrt().max(0.1);
                let min_sep = self.nodes[i].radius + self.nodes[j].radius + 8.0;
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
                // Cap velocity to prevent explosions.
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
