//! Core domain modules for Wolfence.
//!
//! The core layer is where the product's long-lived architecture should settle.
//! It owns repository context collection, normalized findings, orchestrated
//! scanning, and policy-based decision making.

pub mod audit;
pub mod config;
pub mod context;
pub mod findings;
pub mod git;
pub mod hooks;
pub mod orchestrator;
pub mod osv;
pub mod policy;
pub mod receipt_policy;
pub mod receipts;
pub mod scanners;
pub mod trust;
