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

pub(crate) use woody;
pub(crate) use woody_err;
