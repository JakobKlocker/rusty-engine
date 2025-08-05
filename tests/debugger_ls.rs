// In tests/debugger_smoke.rs

use rusty_engine::core::{backtrace::Backtrace, disassemble::Disassembler, stepping::Stepping};

#[test]
fn integration_attach_and_set_breakpoint_on_ls() {
    use rusty_engine::core::debugger::*;
    use rusty_engine::core::stepping::Stepping;
    use std::process::Command;
    use std::thread;
    use std::time::Duration;

    let mut child = Command::new("/home/jakob/projects/rusty-engine/tests/a.out")
        .spawn()
        .expect("failed to spawn ls");
    let pid = nix::unistd::Pid::from_raw(child.id() as i32).as_raw();

    thread::sleep(Duration::from_millis(100));

    let mut dbg = Debugger::attach_to(pid).expect("failed to attach");

    dbg.cont().expect("continue failed");

    let _ = child.kill();
}

#[test]
fn integration_run_disassemble() {
    use rusty_engine::core::debugger::*;
    use rusty_engine::core::stepping::Stepping;
    use std::thread;
    use std::time::Duration;

    let mut dbg = Debugger::launch("/home/jakob/projects/rusty-engine/tests/a.out", &[]).unwrap();
    thread::sleep(Duration::from_millis(500));
    let dis = dbg.disassemble().unwrap();
    println!("{}", dis);
}

#[test]
fn bp_run_test() {
    use rusty_engine::core::debugger::*;
    use rusty_engine::core::stepping::Stepping;
    use std::os::unix::process::CommandExt;
    use std::process::{Child, Command};
    use std::thread;
    use std::time::Duration;

    let mut dbg = Debugger::launch("/home/jakob/projects/rusty-engine/tests/a.out", &[]).unwrap();
    println!("baseaddr: {}", dbg.process.base_addr);
    println!("{:?}", dbg.functions);
    if let Some(func) = dbg.functions.iter().find(|f| f.name == "foo") {
        dbg.set_breakpoint_at_addr(func.offset + dbg.process.base_addr)
            .unwrap();
        println!("func exists");
    }
    dbg.cont();
}

#[test]
fn bp_on_file_line() {
    use rusty_engine::core::debugger::*;

    let mut dbg = Debugger::launch("/home/jakob/projects/rusty-engine/tests/a.out", &[]).unwrap();
    

    dbg.set_breakpoint_at_line("test.c", 4).unwrap();
    dbg.cont();
    dbg.wait();
    println!("{:?}", dbg.backtrace().unwrap());
}
