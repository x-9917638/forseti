mod backend;

mod ui;

use backend::database::*;
use backend::generator::generate_password;
use std::error;

struct State {}

enum Message {}

pub fn run() -> Result<(), String> {
    return Ok(());
}
