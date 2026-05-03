//! Force-directed graph layout engine (Fruchterman-Reingold).
//!
//! Pure Rust, WASM-compatible. Runs tick-by-tick in a Dioxus `use_future`.

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
            alpha_decay: 0.02,
            alpha_min: 0.001,
            velocity_decay: 0.6,
        }
    }

    /// Add a node. Returns its index. If a node with the same ID exists, returns that index.
    pub fn add_node(&mut self, id: String, kind: String, label: String) -> usize {
        if let Some(idx) = self.nodes.iter().position(|n| n.id == id) {
            return idx;
        }
        let angle = self.nodes.len() as f64 * 2.399; // golden angle
        let r = 50.0 + self.nodes.len() as f64 * 15.0;
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

        // Many-body repulsion (direct N^2 — fine for <500 nodes).
        let repulsion_strength = -300.0;
        for i in 0..n {
            for j in (i + 1)..n {
                let dx = self.nodes[j].x - self.nodes[i].x;
                let dy = self.nodes[j].y - self.nodes[i].y;
                let dist_sq = (dx * dx + dy * dy).max(1.0);
                let dist = dist_sq.sqrt();
                let force = repulsion_strength * self.alpha / dist_sq;
                let fx = dx / dist * force;
                let fy = dy / dist * force;
                self.nodes[i].vx -= fx;
                self.nodes[i].vy -= fy;
                self.nodes[j].vx += fx;
                self.nodes[j].vy += fy;
            }
        }

        // Link spring force.
        let link_distance = 100.0;
        let link_strength = 0.3;
        for edge in &self.edges {
            let dx = self.nodes[edge.target].x - self.nodes[edge.source].x;
            let dy = self.nodes[edge.target].y - self.nodes[edge.source].y;
            let dist = (dx * dx + dy * dy).sqrt().max(1.0);
            let force = (dist - link_distance) * link_strength * self.alpha * edge.weight as f64;
            let fx = dx / dist * force;
            let fy = dy / dist * force;
            self.nodes[edge.source].vx += fx;
            self.nodes[edge.source].vy += fy;
            self.nodes[edge.target].vx -= fx;
            self.nodes[edge.target].vy -= fy;
        }

        // Center pull.
        let center_strength = 0.05 * self.alpha;
        for node in &mut self.nodes {
            node.vx -= node.x * center_strength;
            node.vy -= node.y * center_strength;
        }

        // Apply velocity and damping.
        for node in &mut self.nodes {
            if let Some(fx) = node.fx {
                node.x = fx;
                node.vx = 0.0;
            } else {
                node.vx *= self.velocity_decay;
                node.x += node.vx;
            }
            if let Some(fy) = node.fy {
                node.y = fy;
                node.vy = 0.0;
            } else {
                node.vy *= self.velocity_decay;
                node.y += node.vy;
            }
        }

        // Decay alpha.
        self.alpha += (self.alpha_min - self.alpha) * self.alpha_decay;
    }
}
