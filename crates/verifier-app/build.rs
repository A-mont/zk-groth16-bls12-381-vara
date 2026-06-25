// Root build script — builds the app to Wasm, then generates IDL + Rust client.
use sails_client_gen::ClientGenerator;
use std::{
    env,
    fs::File,
    io::{BufRead, BufReader},
    path::PathBuf,
};

fn main() {
    sails_rs::build_wasm();

    if env::var("__GEAR_WASM_BUILDER_NO_BUILD").is_ok() {
        return;
    }

    let bin_path_file = File::open(".binpath").unwrap();
    let mut bin_path_reader = BufReader::new(bin_path_file);
    let mut bin_path = String::new();
    bin_path_reader.read_line(&mut bin_path).unwrap();
    let bin_path = bin_path.trim_end().to_string();

    let mut idl_path = PathBuf::from(bin_path.clone());
    idl_path.set_extension("idl");
    sails_idl_gen::generate_idl_to_file::<zk_verifier_app::Program>(idl_path.clone()).unwrap();

    let mut client_path = PathBuf::from(bin_path + "_client");
    client_path.set_extension("rs");

    ClientGenerator::from_idl_path(&idl_path)
        .generate_to(client_path)
        .unwrap();
}
