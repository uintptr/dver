use std::fmt::Display;

pub fn printkv<D: Display>(k: &str, v: D) {
    let k = format!("{k}:");
    println!("    {k:<20}{v}");
}
