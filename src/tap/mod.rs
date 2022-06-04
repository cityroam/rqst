#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "linux")]
pub use self::linux::*;
#[cfg(windows)]
pub mod windows;
#[cfg(windows)]
pub use self::windows::*;