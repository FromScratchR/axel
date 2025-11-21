macro_rules! axel {
    // Simple message
    ($msg:expr) => {
        println!("[axel] -> {}", $msg);
    };
    // Fmt with args
    ($fmt:literal, $($p:expr),*) => {
        println!("[axel] -> {}", format!($fmt, $($p),*));
    };
}

macro_rules! axel_err {
    ($str:literal) => {
        panic!("[axel] Error -> {}", $str);
    };
    // Fmt with args
    ($fmt:literal, $($p:expr),*) => {
        println!("[axel] Error -> {}", format!($fmt, $($p),*));
    };
}

pub(crate) use axel;
pub(crate) use axel_err;
