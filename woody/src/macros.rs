// TODO set custom macro which generate these macros

macro_rules! woody {
    // Simple message
    ($msg:expr) => {
        println!("[woody] -> {}", $msg);
    };
    // Fmt with args
    ($fmt:literal, $($p:expr),*) => {
        println!("[woody] -> {}", format!($fmt, $($p),*));
    };
}

macro_rules! woody_err {
    ($str:literal) => {
        panic!("[woody] Error -> {}", $str);
    };
    // Fmt with args
    ($fmt:literal, $($p:expr),*) => {
        println!("[woody] Error -> {}", format!($fmt, $($p),*));
    };
}

macro_rules! container {
    // Simple message
    ($msg:expr) => {
        println!("[Container] -> {}", $msg);
    };
    // Fmt with args
    ($fmt:literal, $($p:expr),*) => {
        println!("[Container] -> {}", format!($fmt, $($p),*));
    };
}

macro_rules! container_err {
    // Simple message
    ($msg:expr) => {
        println!("[Container] Error -> {}", $msg);
    };
    // Fmt with args
    ($fmt:literal, $($p:expr),*) => {
        println!("[Container] Error -> {}", format!($fmt, $($p),*));
    };
}

pub(crate) use woody;
pub(crate) use woody_err;
pub(crate) use container;
pub(crate) use container_err;
